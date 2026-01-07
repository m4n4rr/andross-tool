Java.perform(function () {

    const PathClassLoader = Java.use("dalvik.system.PathClassLoader");
    const File = Java.use("java.io.File");
    const FileInputStream = Java.use("java.io.FileInputStream");
    const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");

    PathClassLoader.$init.overload(
        "java.lang.String",
        "java.lang.ClassLoader"
    ).implementation = function (dexPath, parent) {

        console.log("\n[+] PathClassLoader intercepted");
        console.log("    dexPath:", dexPath);

        try {
            const file = File.$new(dexPath);

            if (file.exists()) {

                const fis = FileInputStream.$new(file);
                const baos = ByteArrayOutputStream.$new();
                const buffer = Java.array("byte", Array(4096).fill(0));

                let readCount;
                while ((readCount = fis.read(buffer, 0, buffer.length)) > 0) {
                    baos.write(buffer, 0, readCount);
                }

                fis.close();

                const bytes = baos.toByteArray();

                console.log("    DEX size:", bytes.length);

                let header = "";
                for (let i = 0; i < 16 && i < bytes.length; i++) {
                    header += (bytes[i] & 0xff).toString(16).padStart(2, "0") + " ";
                }
                console.log("    DEX header:", header);

                // Encode DEX bytes as hex string, output in lines
                console.log("[DEX_PAYLOAD_START]");
                
                let hexLine = "";
                const lineWidth = 2048; // Output 2KB per line
                
                for (let i = 0; i < bytes.length; i++) {
                    hexLine += (bytes[i] & 0xff).toString(16).padStart(2, "0");
                    
                    // Output line when it reaches target width
                    if (hexLine.length >= lineWidth) {
                        console.log(hexLine);
                        hexLine = "";
                    }
                }
                
                // Output any remaining hex
                if (hexLine.length > 0) {
                    console.log(hexLine);
                }
                
                console.log("[DEX_PAYLOAD_END]");
            }

        } catch (e) {
            console.log("    [ERROR]");
            console.log(e);
        }

        return this.$init(dexPath, parent);
    };

});
