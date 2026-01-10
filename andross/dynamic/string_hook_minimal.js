Java.perform(function () {

    // Event emitter - outputs structured JSON data to console
    function emitEvent(type, value, caller) {
        var event = {
            type: type,
            value: value,
            caller: caller
        };
        console.log(JSON.stringify(event));
    }

    // Extract first relevant app caller from stack trace
    function getAppCaller() {
        try {
            var Throwable = Java.use("java.lang.Throwable");
            var stack = Throwable.$new().getStackTrace();
            
            for (var i = 0; i < stack.length; i++) {
                var f = stack[i];
                var cls = f.getClassName();
                
                // Look for app package (skip framework/Frida internals)
                if (!cls.startsWith("java.") && 
                    !cls.startsWith("android.") &&
                    !cls.startsWith("com.android.") &&
                    !cls.startsWith("dalvik.")) {
                    return cls + "." + f.getMethodName();
                }
            }
        } catch (e) {
            // Silently fail - return default
        }
        return "unknown.unknown";
    }

    var StringFactory = Java.use("java.lang.StringFactory");
    var StringBuilder = Java.use("java.lang.StringBuilder");
    var StringClass   = Java.use("java.lang.String");
    var BufferedReader = Java.use("java.io.BufferedReader");
    var SharedPreferences = Java.use("android.content.SharedPreferences");

    // ===== StringFactory.newStringFromBytes =====
    StringFactory.newStringFromBytes.overload(
        '[B', 'int', 'int', 'java.nio.charset.Charset'
    ).implementation = function (bytes, offset, length, charset) {
        var str = this.newStringFromBytes(bytes, offset, length, charset);
        if (str && str.length > 0) {
            emitEvent("bytes", str, getAppCaller());
        }
        return str;
    };

    // ===== StringFactory.newStringFromChars =====
    StringFactory.newStringFromChars.overload(
        '[C', 'int', 'int'
    ).implementation = function (chars, offset, length) {
        var str = this.newStringFromChars(chars, offset, length);
        if (str && str.length > 0) {
            emitEvent("chars", str, getAppCaller());
        }
        return str;
    };

    // ===== StringFactory.newStringFromString =====
    StringFactory.newStringFromString.overload(
        'java.lang.String'
    ).implementation = function (s) {
        var str = this.newStringFromString(s);
        if (str && str.length > 0) {
            emitEvent("copy", str, getAppCaller());
        }
        return str;
    };

    // ===== StringBuilder.toString =====
    // DISABLED: to reduce memory pressure in minimal mode

    // ===== String.valueOf(Object) =====
    // DISABLED: to reduce memory pressure in minimal mode

    // ===== String.concat(String) =====
    StringClass.concat.implementation = function (s) {
        var result = this.concat(s);
        if (result && result.length > 0) {
            emitEvent("concat", result, getAppCaller());
        }
        return result;
    };

    // ===== BufferedReader.readLine() =====
    BufferedReader.readLine.implementation = function () {
        var line = this.readLine();
        if (line !== null && line.length > 0) {
            emitEvent("readline", line, getAppCaller());
        }
        return line;
    };

    // ===== SharedPreferences.getString() =====
    SharedPreferences.getString.implementation = function (key, def) {
        var value = this.getString(key, def);
        if (value !== null && value.length > 0) {
            emitEvent("prefs", value, getAppCaller());
        }
        return value;
    };

});
