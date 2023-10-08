import java.io.IOException;

public class RSAEncryption {

    public static void main(String[] args) {
        try {
            // Replace these paths with the actual paths to your input and output files
            String inputPath = "generated_java_privateKey.der";
            String inputPublicPath ="generated_java_publicKey.der";
            
            String outputPath = "Converted_private_key_pkcs8.der";
            String outputPublicPath = "Converted_public_key.der";
            
            // Run the OpenSSL commands to perform the conversion
            ProcessBuilder processBuilder = new ProcessBuilder(
                "openssl",
                "rsa",
                "-inform", "DER",
                "-outform", "PEM",
                "-in", inputPath,
                "-out", "private_key_pkcs1.pem"
            );

            Process process = processBuilder.start();
            int exitCode = process.waitFor();

            if (exitCode == 0) {
                // Conversion from PKCS#1 DER to PEM was successful
                System.out.println("PKCS#1 DER to PEM conversion successful.");

                // Run another OpenSSL command to convert from PEM to PKCS#8 DER
                processBuilder.command(
                    "openssl",
                    "pkcs8",
                    "-topk8",
                    "-inform", "PEM",
                    "-outform", "DER",
                    "-in", "private_key_pkcs1.pem",
                    "-out", outputPath,
                    "-nocrypt"
                );

                process = processBuilder.start();
                exitCode = process.waitFor();

                if (exitCode == 0) {
                    // Conversion from PEM to PKCS#8 DER was successful
                    System.out.println("PEM to PKCS#8 DER conversion successful.");
                    System.out.println("PKCS#8 DER key saved to: " + outputPath);
                } else {
                    // Handle conversion failure
                    System.err.println("Error converting PEM to PKCS#8 DER.");
                }
            } else {
                // Handle conversion failure
                System.err.println("Error converting PKCS#1 DER to PEM.");
            }
            
            ProcessBuilder publicProcessBuilder = new ProcessBuilder(
                    "openssl",
                    "rsa",
                    "-pubin", // Specify that the input is a public key
                    "-inform", "DER",
                    "-outform", "PEM",
                    "-in", inputPublicPath,
                    "-out", "public_key.pem"
                );
            
            Process publicProcess = publicProcessBuilder.start();
            int publicExitCode = publicProcess.waitFor();
            
            if (publicExitCode == 0) {
                // Conversion from DER to PEM was successful
                System.out.println("DER to PEM public key conversion successful.");

                // Run another OpenSSL command to convert from PEM to ASN.1 structures
                publicProcessBuilder.command(
                    "openssl",
                    "asn1parse",
                    "-in", "public_key.pem",
                    "-out", outputPublicPath
                );
                
                
                publicProcess = publicProcessBuilder.start();
                publicExitCode = publicProcess.waitFor();
                
                if (publicExitCode == 0) {
                    // Conversion to ASN.1 structures was successful
                    System.out.println("PEM to ASN.1 public key conversion successful.");
                    System.out.println("ASN.1 public key saved to: " + outputPublicPath);
                } else {
                    // Handle conversion failure
                    System.err.println("Error converting PEM public key to ASN.1 structures.");
                }
            } else {
                // Handle conversion failure
                System.err.println("Error converting DER public key to PEM.");
            }
            
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}
