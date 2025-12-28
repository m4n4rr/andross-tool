Java.perform(function () {

    // stack mapping 
    function printStack() {
        var Throwable = Java.use("java.lang.Throwable");
        var stack = Throwable.$new().getStackTrace();

        for (var i = 0; i < stack.length; i++) {
            var f = stack[i];
            var cls = f.getClassName();
            if (cls.startsWith("com.example")) {
                console.log("    at " + cls + "." + f.getMethodName());
                break;
            }
        }
    }

    var StringFactory = Java.use("java.lang.StringFactory");
    var StringBuilder = Java.use("java.lang.StringBuilder");
    var StringClass   = Java.use("java.lang.String");
    var BufferedReader = Java.use("java.io.BufferedReader");
    var SharedPreferences = Java.use("android.content.SharedPreferences");

    // byte[]
    StringFactory.newStringFromBytes.overload(
        '[B', 'int', 'int', 'java.nio.charset.Charset'
    ).implementation = function (bytes, offset, length, charset) {
        var str = this.newStringFromBytes(bytes, offset, length, charset);
        console.log("[String][bytes] =>", str);
        printStack();
        return str;
    };

    // char[]
    StringFactory.newStringFromChars.overload(
        '[C', 'int', 'int'
    ).implementation = function (chars, offset, length) {
        var str = this.newStringFromChars(chars, offset, length);
        console.log("[String][chars] =>", str);
        printStack();
        return str;
    };

    // copy
    StringFactory.newStringFromString.overload(
        'java.lang.String'
    ).implementation = function (s) {
        var str = this.newStringFromString(s);
        console.log("[String][copy] =>", str);
        printStack();
        return str;
    };

    // ===== StringBuilder =====

    StringBuilder.toString.implementation = function () {
        var result = this.toString();
        console.log("[String][StringBuilder] =>", result);
        printStack();
        return result;
    };

    // ===== NEW ADDITIONS =====

    // String.valueOf(Object)
    StringClass.valueOf.overload('java.lang.Object').implementation = function (obj) {
        var result = this.valueOf(obj);
        console.log("[String][valueOf(Object)] =>", result);
        printStack();
        return result;
    };

    // String.concat(String)
    StringClass.concat.implementation = function (s) {
        var result = this.concat(s);
        console.log("[String][concat] =>", result);
        printStack();
        return result;
    };

    // BufferedReader.readLine()
    BufferedReader.readLine.implementation = function () {
        var line = this.readLine();
        if (line !== null) {
            console.log("[String][BufferedReader.readLine] =>", line);
            printStack();
        }
        return line;
    };

    // SharedPreferences.getString(key, def)
    SharedPreferences.getString.implementation = function (key, def) {
        var value = this.getString(key, def);
        console.log("[String][SharedPreferences] key =", key, "value =", value);
        printStack();
        return value;
    };

});
