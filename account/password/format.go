package password

import (
	"strconv"
	"strings"
)

// phcConfig is a struct required for creating a PHC string
type phcConfig struct {
	ID      string
	Version int
	Params  map[string]interface{}
	Salt    string
	Hash    string
}

// serialize converts PHCConfig struct into a PHC string.
// See https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
func serialize(config phcConfig) string {
	var params []string
	for key, value := range config.Params {
		switch v := value.(type) {
		case string:
			params = append(params, key+"="+v)
		case int:
			params = append(params, key+"="+strconv.Itoa(v))
		}

	}
	return "$" + config.ID + "$v=" + strconv.Itoa(config.Version) + "$" + strings.Join(params, ",") + "$" + config.Salt + "$" + config.Hash
}

// deserialize converts a PHC string into a PHCConfig struct
func deserialize(hash string) phcConfig {
	hashArray := strings.Split(hash, "$")
	params := make(map[string]interface{})

	if len(hashArray[3]) != 0 {
		paramsArray := strings.Split(hashArray[3], ",")
		for _, value := range paramsArray {
			pair := strings.Split(value, "=")
			params[pair[0]] = pair[1]
		}
	}

	version, _ := strconv.Atoi(strings.Replace(hashArray[2], "v=", "", 1))
	return phcConfig{
		ID:      hashArray[1],
		Version: version,
		Params:  params,
		Salt:    hashArray[4],
		Hash:    hashArray[5],
	}
}
