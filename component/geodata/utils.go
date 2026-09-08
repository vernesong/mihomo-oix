package geodata

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/metacubex/mihomo/common/singleflight"
	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/oschwald/maxminddb-golang"
	"google.golang.org/protobuf/proto"
)

var (
	geoMode        bool
	geoLoaderName  = "memconservative"
	geoSiteMatcher = "succinct"
)

//  geoLoaderName = "standard"

func GeodataMode() bool {
	return geoMode
}

func LoaderName() string {
	return geoLoaderName
}

func SiteMatcherName() string {
	return geoSiteMatcher
}

func SetGeodataMode(newGeodataMode bool) {
	geoMode = newGeodataMode
}

func SetLoader(newLoader string) {
	if newLoader == "memc" {
		newLoader = "memconservative"
	}
	geoLoaderName = newLoader
}

func SetSiteMatcher(newMatcher string) {
	switch newMatcher {
	case "mph", "hybrid":
		geoSiteMatcher = "mph"
	default:
		geoSiteMatcher = "succinct"
	}
}

func verifyGeodata(r io.Reader) error {
	br := bufio.NewReader(r)
	first := true
	for {
		tag, err := br.ReadByte()
		if err == io.EOF {
			if first {
				return fmt.Errorf("invalid geodata file: empty file")
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("invalid geodata file: %w", err)
		}
		first = false
		if tag != 0x0A {
			return fmt.Errorf("invalid geodata file: unexpected byte 0x%02X", tag)
		}

		entryLen, err := binary.ReadUvarint(br)
		if err != nil {
			return fmt.Errorf("invalid geodata file: truncated varint: %w", err)
		}
		if entryLen == 0 {
			return fmt.Errorf("invalid geodata file: zero-length entry")
		}
		if entryLen > math.MaxInt64 {
			return fmt.Errorf("invalid geodata file: entry length overflow")
		}
		if _, err := io.CopyN(io.Discard, br, int64(entryLen)); err != nil {
			return fmt.Errorf("invalid geodata file: truncated entry: %w", err)
		}
	}
}

func verifyGeodataFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return verifyGeodata(f)
}

func VerifyMMDBBytes(data []byte) error {
	reader, err := maxminddb.FromBytes(data)
	if err != nil {
		return err
	}
	defer reader.Close()
	networks := reader.Networks(maxminddb.SkipAliasedNetworks)
	records := 0
	for networks.Next() {
		var record any
		if _, err := networks.Network(&record); err != nil {
			return err
		}
		records++
	}
	if err := networks.Err(); err != nil {
		return err
	}
	if records == 0 {
		return fmt.Errorf("empty MMDB database")
	}
	return nil
}

func VerifyGeodataBytes(data []byte) error {
	return verifyGeodata(bytes.NewReader(data))
}

// VerifyGeoIPBytes and VerifyGeoSiteBytes decode every record before a
// downloaded candidate wins; valid outer framing alone is not enough.
func VerifyGeoIPBytes(data []byte) error {
	var database router.GeoIPList
	if err := proto.Unmarshal(data, &database); err != nil {
		return err
	}
	if len(database.Entry) == 0 {
		return fmt.Errorf("empty GeoIP database")
	}
	for _, entry := range database.Entry {
		if entry.CountryCode == "" {
			return fmt.Errorf("GeoIP entry has no country code")
		}
		for _, cidr := range entry.Cidr {
			if len(cidr.Ip) != 4 && len(cidr.Ip) != 16 || cidr.Prefix > uint32(len(cidr.Ip)*8) {
				return fmt.Errorf("invalid GeoIP CIDR")
			}
		}
	}
	return nil
}

func VerifyGeoSiteBytes(data []byte) error {
	var database router.GeoSiteList
	if err := proto.Unmarshal(data, &database); err != nil {
		return err
	}
	if len(database.Entry) == 0 {
		return fmt.Errorf("empty GeoSite database")
	}
	for _, entry := range database.Entry {
		if entry.CountryCode == "" {
			return fmt.Errorf("GeoSite entry has no country code")
		}
		for _, domain := range entry.Domain {
			if domain.Type < router.Domain_Plain || domain.Type > router.Domain_Full {
				return fmt.Errorf("invalid GeoSite domain type")
			}
		}
	}
	return nil
}

func Verify(name string) error {
	switch name {
	case C.GeositeName:
		return verifyGeodataFile(C.Path.GeoSite())
	case C.GeoipName:
		return verifyGeodataFile(C.Path.GeoIP())
	default:
		return fmt.Errorf("not support name")
	}
}

var loadGeoSiteMatcherListSF = singleflight.Group[[]*router.Domain]{StoreResult: true}
var loadGeoSiteMatcherSF = singleflight.Group[router.DomainMatcher]{StoreResult: true}

func LoadGeoSiteMatcher(countryCode string) (router.DomainMatcher, error) {
	if countryCode == "" {
		return nil, fmt.Errorf("country code could not be empty")
	}

	not := false
	if countryCode[0] == '!' {
		not = true
		countryCode = countryCode[1:]
		if countryCode == "" {
			return nil, fmt.Errorf("country code could not be empty")
		}
	}
	countryCode = strings.ToLower(countryCode)

	parts := strings.Split(countryCode, "@")
	listName := strings.TrimSpace(parts[0])
	attrVal := parts[1:]
	attrs := parseAttrs(attrVal)

	if listName == "" {
		return nil, fmt.Errorf("empty listname in rule: %s", countryCode)
	}

	matcherName := listName
	if !attrs.IsEmpty() {
		matcherName += "@" + attrs.String()
	}
	matcher, err, shared := loadGeoSiteMatcherSF.Do(matcherName, func() (router.DomainMatcher, error) {
		log.Infoln("Load GeoSite rule: %s", matcherName)
		domains, err, shared := loadGeoSiteMatcherListSF.Do(listName, func() ([]*router.Domain, error) {
			geoLoader, err := GetGeoDataLoader(geoLoaderName)
			if err != nil {
				return nil, err
			}
			return geoLoader.LoadGeoSite(listName)
		})
		if err != nil {
			if !shared {
				loadGeoSiteMatcherListSF.Forget(listName) // don't store the error result
			}
			return nil, err
		}

		if attrs.IsEmpty() {
			if strings.Contains(countryCode, "@") {
				log.Warnln("empty attribute list: %s", countryCode)
			}
		} else {
			filteredDomains := make([]*router.Domain, 0, len(domains))
			hasAttrMatched := false
			for _, domain := range domains {
				if attrs.Match(domain) {
					hasAttrMatched = true
					filteredDomains = append(filteredDomains, domain)
				}
			}
			if !hasAttrMatched {
				log.Warnln("attribute match no rule: geosite: %s", countryCode)
			}
			domains = filteredDomains
		}

		/**
		linear: linear algorithm
		matcher, err := router.NewDomainMatcher(domains)
		mph：minimal perfect hash algorithm
		*/
		if geoSiteMatcher == "mph" {
			return router.NewMphMatcherGroup(domains)
		} else {
			return router.NewSuccinctMatcherGroup(domains)
		}
	})
	if err != nil {
		if !shared {
			loadGeoSiteMatcherSF.Forget(matcherName) // don't store the error result
		}
		return nil, err
	}
	if not {
		matcher = router.NewNotDomainMatcherGroup(matcher)
	}

	return matcher, nil
}

var loadGeoIPMatcherSF = singleflight.Group[router.IPMatcher]{StoreResult: true}

func LoadGeoIPMatcher(country string) (router.IPMatcher, error) {
	if len(country) == 0 {
		return nil, fmt.Errorf("country code could not be empty")
	}

	not := false
	if country[0] == '!' {
		not = true
		country = country[1:]
	}
	country = strings.ToLower(country)

	matcher, err, shared := loadGeoIPMatcherSF.Do(country, func() (router.IPMatcher, error) {
		log.Infoln("Load GeoIP rule: %s", country)
		geoLoader, err := GetGeoDataLoader(geoLoaderName)
		if err != nil {
			return nil, err
		}
		cidrList, err := geoLoader.LoadGeoIP(country)
		if err != nil {
			return nil, err
		}
		return router.NewGeoIPMatcher(cidrList)
	})
	if err != nil {
		if !shared {
			loadGeoIPMatcherSF.Forget(country) // don't store the error result
			log.Warnln("Load GeoIP rule: %s", country)
		}
		return nil, err
	}
	if not {
		matcher = router.NewNotIpMatcherGroup(matcher)
	}
	return matcher, nil
}

func ClearGeoSiteCache() {
	loadGeoSiteMatcherListSF.Reset()
	loadGeoSiteMatcherSF.Reset()
}

func ClearGeoIPCache() {
	loadGeoIPMatcherSF.Reset()
}
