rule Hello 
{ 
  strings: 
    $ascii = "hola"

  condition: 
    $ascii 
}

rule SUSP_obfuscated_JS_obfuscatorio
{
    meta:
    
        author      = "@imp0rtp3"
        description = "Detect JS obfuscation done by the js obfuscator (often malicious)"
        reference   = "https://obfuscator.io"

    strings:

        // Beggining of the script
        $a1 = "var a0_0x"
        $a2 = /var _0x[a-f0-9]{4}/
        
        // Strings to search By number of occurences
        $b1 = /a0_0x([a-f0-9]{2}){2,4}\('?0x[0-9a-f]{1,3}'?\)/
        $b2 =/[^\w\d]_0x([a-f0-9]{2}){2,4}\('?0x[0-9a-f]{1,3}'?\)[^\w\d]/
        $b3 = /[^\w\d]_0x([a-f0-9]{2}){2,4}\['push'\]\(_0x([a-f0-9]{2}){2,4}\['shift'\]\(\)[^\w\d]/
        $b4 = /!0x1[^\d\w]/
        $b5 = /[^\w\d]function\((_0x([a-f0-9]{2}){2,4},)+_0x([a-f0-9]{2}){2,4}\)\s?\{/
        $b6 = /[^\w\d]_0x([a-f0-9]{2}){2,4}\s?=\s?_0x([a-f0-9]{2}){2,4}[^\w\d]/
        
        // generic strings often used by the obfuscator
        $c1 = "))),function(){try{var _0x"
        $c2 = "=Function('return\\x20(function()\\x20'+'{}.constructor(\\x22return\\x20this\\x22)(\\x20)'+');');"
        $c3 = "['atob']=function("
        $c4 = ")['replace'](/=+$/,'');var"
        $c5 = "return!![]"
        $c6 = "'{}.constructor(\\x22return\\\x20this\\x22)(\\x20)'"
        $c7 = "{}.constructor(\x22return\x20this\x22)(\x20)" base64
        $c8 = "while(!![])"
        $c9 = "while (!![])"

        // Strong strings
        $d1 = /(parseInt\(_0x([a-f0-9]{2}){2,4}\(0x[a-f0-9]{1,5}\)\)\/0x[a-f0-9]{1,2}\)?(\+|\*\()\-?){6}/
                
    condition:
        $a1 at 0 or
        $a2 at 0 or
        (
            filesize<1000000 and
            (
                (#b1 + #b2) > (filesize \ 200) or
                #b3 > 1 or
                #b4 > 10 or
                #b5 > (filesize \ 2000) or
                #b6 > (filesize \ 200) or
                3 of ($c*) or
                $d1
            )
        )
}

rule Detect_Spaces_Followed_By_Eval_Require {
    meta:
        description = "Detects an eval or require hidden beyond a lot of whitespaces"
    strings:
        $spaces_eval = /.{,50}[\s]{1000,}eval\(/
        $spaces_require = /.{,50}[\s]{1000,}require\(/
    condition:
        $spaces_eval or $spaces_require
}

rule JavaScript_Patterns_Beavertail {
    meta:
        description = "Regla para detectar ciertos patrones específicos en JavaScript para payloads de Beavertail"
        author = "Threat Intel"

    strings:
        // Detecta espacios antes de Object.prototype
        $space_object_prototype = /\s*Object\.prototype/
        
        // La expresión regular detecta el patrón clearInterval en el final
        $clear_interval = /clearInterval\(.{1,4}\)\}\),6e5\);/

        // Detecta el uso de "base64" seguido de "utf8" en la misma secuencia
        $base64_utf8 = /"base64",.{1,4}"utf8"/

        // Metamask wallet Chrome extension
        $wallet1 = "nkbihfbeo" base64
        $wallet2= "nkbihfbeogae" base64
        $wallet3 = "nkbihfbeogaeaoe" base64
        $wallet4 = "nkbihfbeogaeaoehlefnkodbefgpgknn" base64
    
    condition:
       $space_object_prototype and 
       (
            1 of ($wallet*)
            or
            2 of ($clear_interval, $base64_utf8) 
        )
}
rule Detect_Http_Requests_NodeJS_And_Eval
{
    meta:
        description = "Detecta llamadas HTTP en Node.js y eval()"

    strings:
        // Indicadores de que el código pertenece a Node.js

        // Llamadas HTTP en Node.js
        $fetch_call = /\bfetch\s*\(\s*["'](http|https):\/\// nocase
        $get_call = /(\b|\.)get\s*\(\s*["'](http|https):\/\// nocase
        $post_call = /(\b|\.)post\s*\(\s*["'](http|https):\/\// nocase
        $put_call = /(\b|\.)put\s*\(\s*["'](http|https):\/\// nocase
        $patch_call = /(\b|\.)patch\s*\(\s*["'](http|https):\/\// nocase
        $delete_call = /(\b|\.)delete\s*\(\s*["'](http|https):\/\// nocase

        // Import de libs http
        $libs_require = /require\s*\(["']\s*(request|axios)["']\s*\)/ nocase
        $libs_import = /import(.*from)?\s+['"](request|axios)['"]/ nocase

        // Eval real (sin falsos positivos como browser.eval)
        $eval_real = /\beval\s*\(\s*([\"'][^\"']*[\"']|\w+)/ 

        // Construccion de funciones dinamicas
        $func_constructor = /new\s+\(?Function(\.constructor\))?\s*\(.{,10000}\)/

    condition:
        any of ($fetch_call, $get_call, $post_call, $put_call, $patch_call, $delete_call, $libs_require, $libs_import) and ($eval_real or $func_constructor)
}
