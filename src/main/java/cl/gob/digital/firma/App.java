package cl.gob.digital.firma;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.nio.charset.StandardCharsets;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.io.FileOutputStream;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignature;
import java.nio.file.Path;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import com.google.gson.Gson;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class App
{
    public static final String ENTITY = "Subsecretaría General de la Presidencia";
    public static final String RUN ="22222222";
    public static final String PURPOSE = "Desatendido";
    public static final String SECRET_KEY = "27a216342c744f89b7b82fa290519ba0";
    public static final String ENDPOINT_API = "https://api.firma.cert.digital.gob.cl/firma/v2/files/tickets";

    public static final String PDF_PATH = "/Users/sebavidal/Downloads/pdf-de-prueba-original.pdf";

    public static void main( String[] args )
    {
        // leer el archivo desde PDF_ORIGINAL y pasarlo a byte[]
        try {
            // crear un nuevo archivo igual al original y guardarlo en PDF_FOLDER_PATH
            Path originalPath = Paths.get(PDF_PATH);
            Path parentDirectoryPath = originalPath.getParent();
            String originalFileName = originalPath.getFileName().toString();
            String currentDateTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
            String newFileName = currentDateTime +"-"+ originalFileName;
            Path newFilePath = parentDirectoryPath.resolve(newFileName);

            if (Files.exists(newFilePath)) {
                throw new IOException("El archivo ya existe: " + newFilePath);
            }

            Files.copy(originalPath, newFilePath);

            byte [] pdf = Files.readAllBytes(Paths.get(newFilePath.toUri()));
            PdfReader reader = new PdfReader(pdf);
            ByteArrayOutputStream bos=new ByteArrayOutputStream();
            long initTime = System.currentTimeMillis();
            PdfSignatureAppearance appearance;
            try {
                appearance = generateAppearance(reader, bos, initTime);

                // obtener hash en base64 del archivo
                String hash = getHash(appearance);
                System.out.println("Hash del archivo: " + hash);

                // llamar al endpoint para firmar el hash y obtener la respuesta
                String contentResponse = callEndpointToSign(hash);

                // decodificar el hash firmado
                System.out.println("Decodificando el content firmado");
                byte[] decodeArr = java.util.Base64.getDecoder().decode(contentResponse);

                // escribir el hash firmado en un archivo
                System.out.println("Incorporando la firma al documento Pdf");
                byte[] paddedSig = new byte[15000];
                System.arraycopy(decodeArr, 0, paddedSig, 0, decodeArr.length);
                PdfDictionary dic2 = new PdfDictionary();
                dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
                appearance.close(dic2);

                // escribir el archivo firmado en la ruta PDF_PATH_END
                String PDF_PATH_END = newFilePath.toString().replace(".pdf", "-firmado.pdf");
                System.out.println("El documento se genero exitosamente en: " + PDF_PATH_END);
                FileOutputStream fos = new FileOutputStream(PDF_PATH_END);
                bos.writeTo(fos);
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public static String callEndpointToSign(String hash) throws IOException {
        System.out.println("Inicio de llamada al endpoint de FirmaGob");

        // Crear el jwt para el token
        String token = createJWT();

        Map<String, Object> requestBody = new HashMap<String, Object>();
        requestBody.put("token", token);
        requestBody.put("api_token_key", "sandbox");

        // crear primer hash (se debe agregar uno por cada archivo que se envia)
        Map<String, Object> hash1 = new HashMap<String, Object>();
        hash1.put("content-type", "application/pdf");
        hash1.put("content", hash);

        // crear arreglo de hashes
        Map<String, Object>[] hashes = (Map<String, Object>[]) Array.newInstance(Map.class, 1);
        hashes[0] = hash1;

        // agregar arreglo de hashes al requestBody
        requestBody.put("hashes", hashes);

        Gson gson = new Gson();
        String jsonBody = gson.toJson(requestBody);

        URL urlObj = new URL(ENDPOINT_API);
        HttpURLConnection con = (HttpURLConnection) urlObj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        con.setDoOutput(true);

        OutputStream os = con.getOutputStream();
        byte[] input = jsonBody.getBytes(StandardCharsets.UTF_8);
        os.write(input, 0, input.length);
        int statusCode = con.getResponseCode();

        // Leer la respuesta
        System.out.println("Leyendo respuesta del endpoint");
        BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        if(statusCode == 200) {
            System.out.println("Llamada al endpoint exitosa, se retornara el content del hash firmado");

            Gson gsonResponse = new Gson();
            responseToJson myObject = gsonResponse.fromJson(response.toString(), responseToJson.class);

            return myObject.getHashes()[0].getContent();
        } else {
            System.out.println("Error al llamar al endpoint");
        }

        con.disconnect();
        return null;
    }

    public static String createJWT() {
        // Crear el JWT
        String token = null;
        // esto permite que la fecha del token siempre sea valida
        String expiration_date_time = LocalDateTime.now().plusMinutes(5).format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss"));
        try {
            String jwtToken = Jwts.builder()
                .claim("entity", ENTITY)
                .claim("run", RUN)
                .claim("expiration", expiration_date_time)
                .claim("purpose", PURPOSE)
                .setIssuedAt(new Date())
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY.getBytes("UTF-8"))
                .compact();

            System.out.println("Token generado: " + jwtToken);
            token = jwtToken;
        } catch (Exception e) {
            //Invalid Signing configuration / Couldn't convert Claims.
        }
        return token;
    }

    public static String getHash(PdfSignatureAppearance appearance) throws IOException {
        // Lee el archivo en un arreglo de bytes
        String hashBase64 = null;

        try {
            InputStream signable = appearance.getRangeStream();
            byte[] bufsig = new byte[8192];
			MessageDigest mdig = MessageDigest.getInstance("SHA-256");

            int n;
            while ((n = signable.read(bufsig)) > 0) {
                mdig.update(bufsig, 0, n);
            }
            byte hash[]  = mdig.digest();
            hashBase64 = Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return hashBase64;
    }

    public static PdfSignatureAppearance generateAppearance(PdfReader reader, ByteArrayOutputStream bos, long initTime)throws Exception {
        PdfStamper stamper=PdfStamper.createSignature(reader, bos, '\0', null, true);
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();

        int contentEstimated = 15000;
        PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("adbe.pkcs7.detached"));
        dic.setReason(appearance.getReason());
	   	dic.setLocation(appearance.getLocation());
	   	dic.setContact(appearance.getContact());
	   	dic.setDate(new PdfDate(appearance.getSignDate()));
	   	appearance.setCryptoDictionary(dic);
		HashMap<PdfName,Integer> exc = new HashMap<PdfName, Integer>();
		exc.put(PdfName.CONTENTS, new Integer(contentEstimated * 2 + 2));

        try {
            appearance.preClose(exc);
        } catch (Exception e) {
            // TODO: handle exception
        }

        return appearance;
    }

    public static PdfStamper createPdfStamperSignature(PdfReader pdfReader, ByteArrayOutputStream byteArrayOutputStream) {
        PdfStamper pdfStamper = null;
        try {
            pdfStamper = PdfStamper.createSignature(pdfReader, byteArrayOutputStream, '\0', null, true);
            pdfStamper.getWriter().setCompressionLevel(5);
            pdfStamper.setFullCompression();
        } catch(IOException e) {
            e.printStackTrace();
        } catch (DocumentException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return pdfStamper;
    }

    static class responseToJson {
        private Hash[] hashes;
        private Metadata metadata;
        private long idSolicitud;

        public Hash[] getHashes() {
            return hashes;
        }

        public Metadata getMetadata() {
            return metadata;
        }

        public long getIdSolicitud() {
            return idSolicitud;
        }
    }

    static class Hash {
        private String content;
        private String status;
        private String contentType;
        private String documentStatus;
        private String hashOriginal;

        public String getContent() {
            return content;
        }

        public String getStatus() {
            return status;
        }

        public String getContentType() {
            return contentType;
        }

        public String getDocumentStatus() {
            return documentStatus;
        }

        public String getHashOriginal() {
            return hashOriginal;
        }
    }

    static class Metadata {
        private boolean otpExpired;
        private int hashesSigned;
        private int signedFailed;
        private int hashesReceived;

        public boolean isOtpExpired() {
            return otpExpired;
        }

        public int getHashesSigned() {
            return hashesSigned;
        }

        public int getSignedFailed() {
            return signedFailed;
        }

        public int getHashesReceived() {
            return hashesReceived;
        }
    }

}
