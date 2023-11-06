import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Base64;


public class DeviceInfoGetter {
    public static void main(String[] args) {
        String ipaddr = "YOUR_IP_ADDRESS";
        int port = YOUR_PORT;
        String location = "YOUR_LOCATION";
        String username = "YOUR_USERNAME";
        String password = "YOUR_PASSWORD";

        try {
            System.out.println(".........Getting device info");

            String CRLF = "\r\n";

            String httpHeader = "POST " + location + " HTTP/1.1" + CRLF +
                    "Host: " + ipaddr + ":" + port + CRLF +
                    "Content-Type: application/soap+xml; action=http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation" + CRLF +
                    "Content-Length: ";

            String[] authInfo = getAuth(username, password);
            String pdigest = authInfo[0];
            String date = authInfo[1];
            String nonce = authInfo[2];

            String httpPayload = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" + CRLF +
                    "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"" + CRLF +
                    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"" + CRLF +
                    "xmlns:tt=\"http://www.onvif.org/ver10/schema\"" + CRLF +
                    "xmlns:s=\"http://www.w3.org/2001/XMLSchema\">" + CRLF +
                    "<soap:Header>" + CRLF +
                    "<Security s:mustUnderstand=\"1\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">" + CRLF +
                    "<UsernameToken>" + CRLF +
                    "<Username>" + username + "</Username>" + CRLF +
                    "<Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">" + pdigest + "</Password>" + CRLF +
                    "<Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">" + nonce + "</Nonce>" + CRLF +
                    "<Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" + date + "</Created>" + CRLF +
                    "</UsernameToken>" + CRLF +
                    "</Security>" + CRLF +
                    "</soap:Header>" + CRLF +
                    "<soap:Body>" + CRLF +
                    "<tds:GetDeviceInformation/>" + CRLF +
                    "</soap:Body>" + CRLF +
                    "</soap:Envelope>";

            httpHeader += httpPayload.length() + CRLF + CRLF;
            String msg = httpHeader + httpPayload;

            String host = ipaddr;
            int PORT = port;

            System.out.println("Sending message");

            try (Socket socket = new Socket(host, PORT);
                 OutputStream out = socket.getOutputStream();
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))) {

                out.write(msg.getBytes(StandardCharsets.UTF_8));
                out.flush();

                StringBuilder response = new StringBuilder();
                String line;
                while ((line = in.readLine()) != null) {
                    response.append(line);
                }

                System.out.println("Received: " + response.toString());

                String manufacturer = parseValue(response.toString(), "Manufacturer");
                String model = parseValue(response.toString(), "Model");
                String firmware = parseValue(response.toString(), "FirmwareVersion");
                String serial = parseValue(response.toString(), "SerialNumber");

                System.out.println(manufacturer + " " + model + " " + firmware + " " + serial);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String[] getAuth(String username, String password) {
        // Implement your authentication logic here
        String pdigest = "YOUR_P_DIGEST";
        String date = "YOUR_DATE";
        String nonce = "YOUR_NONCE";
        return new String[]{pdigest, date, nonce};
    }

    private static String parseValue(String response, String tag) {
        int startInd = response.indexOf("<" + tag + ">") + tag.length() + 2;
        int endInd = response.indexOf("</" + tag + ">", startInd);
        return response.substring(startInd, endInd);
    }
}
