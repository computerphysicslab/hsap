/*
When debugging your code in goLang you may need a pretty print function not just for int or strings,
but capable to render any kind of data structure. Here it is, simple and useful. Enjoy it!
*/

package libstruct

import (
	"encoding/json"
	"fmt"
	"reflect"
)

func interface2string(i interface{}) string {
	pretty, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		fmt.Println("error: ", err)
	}
	return string(pretty)
}

func printStatic(s string, i interface{}) {
	pretty := interface2string(i)
	fmt.Printf("\nlibstruct: %s (%s) => %s\n", s, reflect.TypeOf(i).String(), string(pretty))
	// fmt.Printf("\n\nlibstruct: %s RAW => %s", s, i)
	// fmt.Printf("\n\nlibstructPlain: %+v\n", i)
}

// Print Debugging function to show a data structure w/ pretty style
// If called w/ 1 parameter, it just show its value
// If call w/ 2 parameters, the first one should be the name of the structure to enhance debug visibility
func Print(params ...interface{}) {
	if len(params) == 0 {
		fmt.Println("\nError: not enough parameters when calling Print function")
	} else if len(params) == 1 {
		printStatic("", params[0])
	} else if len(params) == 2 {
		switch params[0].(type) {
		case string:
			printStatic(params[0].(string), params[1])
		default:
			printStatic("", params[0])
			printStatic("", params[1])
		}
	} else {
		fmt.Println("\nError: too many parameters when calling Print function")
	}
}
