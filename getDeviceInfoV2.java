import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Base64;

public class RSAEncryption {
    public static void main(String[] args) {
        // Configuration for local IP and port
        String localIp = "192.168.56.1"; // Replace with your local IP address
        int localPort = 8888; // Replace with your local port number

        try {
            // Multicast group configuration
            InetAddress multicastGroup = InetAddress.getByName("239.255.255.250");
            int multicastPort = 3702;
            int multicastTtl = 2;

            // Create a multicast socket
            MulticastSocket socket = new MulticastSocket(multicastPort);
            socket.setInterface(InetAddress.getByName(localIp));
            socket.joinGroup(multicastGroup);

            // Generate a unique UUID for the discovery message
            String uuid = UUID.randomUUID().toString();

            // Build the SOAP discovery message
            String discoveryMessage = buildDiscoveryMessage(uuid);
            System.out.println(discoveryMessage);
            // Send the SOAP discovery message
            DatagramPacket packet = new DatagramPacket(
                discoveryMessage.getBytes(StandardCharsets.UTF_8),
                discoveryMessage.length(),
                multicastGroup,
                multicastPort
            );

            socket.send(packet);

            while (true) {
                // Receive responses
                byte[] buffer = new byte[10240];

                System.out.println("Waiting for responses...");

                DatagramPacket responsePacket = new DatagramPacket(buffer, buffer.length);

                socket.receive(responsePacket);

                String response = new String(buffer, 0, responsePacket.getLength(), StandardCharsets.UTF_8);

                // Process the received response
                processResponse(response);

                // Sleep for a while before checking for more responses
                TimeUnit.SECONDS.sleep(5);
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

        // Replace with your specific device information
        String ipaddr = "192.168.1.100";  // Replace with the IP address of your device
        int port = 80;                   // Replace with the port number of your device's HTTP service
        String location = "/onvif/device_service"; // Replace with the actual location
        String username = "your_username"; // Replace with your username
        String password = "your_password"; // Replace with your password

        try {
            // Create a socket to connect to the device
            InetAddress host = InetAddress.getByName(ipaddr);
            Socket socket = new Socket(host, port);

            // Get the current date in the required format
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            String date = dateFormat.format(new Date());

            // Generate a random nonce
            String nonce = Base64.getEncoder().encodeToString(date.getBytes());

            // Calculate the password digest
            String pdigest = getPasswordDigest(nonce, date, password);

            // Construct the HTTP request header
            String httpHeader = "POST " + location + " HTTP/1.1\r\n" +
                    "Host: " + ipaddr + ":" + port + "\r\n" +
                    "Content-Type: application/soap+xml; action=\"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation\"\r\n" +
                    "Content-Length: ";

            // Construct the SOAP request payload
            String soapPayload = "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope/\" " +
            	    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl/\" " +
            	    "xmlns:tt=\"http://www.onvif.org/ver10/schema/\" " +
            	    "xmlns:s=\"http://www.w3.org/2001/XMLSchema/\">\n" +
            	    "<soap:Header>\n" +
            	    "  <Security s:mustUnderstand=\"1\" " +
            	    "xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd/\">\n" +
            	    "    <UsernameToken>\n" +
            	    "      <Username>" + username + "</Username>\n" +
            	    "      <Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">" + pdigest + "</Password>\n" +
            	    "      <Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">" + nonce + "</Nonce>\n" +
            	    "      <Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd/\">" + date + "</Created>\n" +
            	    "    </UsernameToken>\n" +
            	    "  </Security>\n" +
            	    "</soap:Header>\n" +
            	    "<soap:Body>\n" +
            	    "  <tds:GetDeviceInformation/>\n" +
            	    "</soap:Body>\n" +
            	    "</soap:Envelope>";


            // Calculate the content length
            int contentLength = soapPayload.length();

            // Add the content length to the HTTP header
            httpHeader += contentLength + "\r\n\r\n";

            // Construct the full HTTP request
            String httpRequest = httpHeader + soapPayload;

            // Send the HTTP request to the device
            PrintWriter out = new PrintWriter(socket.getOutputStream());
            out.print(httpRequest);
            out.flush();

            // Receive and print the response from the device
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String response;
            while ((response = in.readLine()) != null) {
                System.out.println("Received: " + response);
                // Parse and process the response here
            }

            // Close the socket
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Function to build the SOAP discovery message
    private static String buildDiscoveryMessage(String uuid) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\"" +
            " xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"" +
            " xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"" +
            " xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">" +
            "<e:Header>" +
            "<w:MessageID>uuid:" + uuid + "</w:MessageID>" +
            "<w:To e:mustUnderstand=\"true\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>" +
            "<w:Action a:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>" +
            "</e:Header>" +
            "<e:Body>" +
            "<d:Probe>" +
            "<d:Types>dn:NetworkVideoTransmitter</d:Types>" +
            "</d:Probe>" +
            "</e:Body>" +
            "</e:Envelope>";
    }

    // Function to process the received response
    private static void processResponse(String response) {
        System.out.println("Received response: " + response);

        // Check if the response contains specific information
        if (response.contains("/VIPER-IR-Camera") && response.contains("onvif://www.onvif.org/manufacturer/RealTime7-Inc")) {
            System.out.println("Found VIPER CAMERA");
        }
    }

    // Function to calculate the password digest
    private static String getPasswordDigest(String nonce, String created, String password) {
        try {
            String concatenated = nonce + created + password;
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(concatenated.getBytes(StandardCharsets.UTF_8));
            byte[] digest = md.digest();
            return Base64.getEncoder().encodeToString(digest);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
}
