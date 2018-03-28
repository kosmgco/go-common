package stringUtils

import "encoding/json"

func IsInSlice(a interface{}, as []interface{}) bool {
    for _, item := range as{
        if a == item {
            return true
        }
    }
    return false
}

func JsonNumberToInt64(n json.Number) (int64, error) {
    return n.Int64()
}