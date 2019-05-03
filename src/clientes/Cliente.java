package clientes;
import org.bouncycastle.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.cert.CertificateException;
import javax.xml.bind.DatatypeConverter;

public class Cliente 
{
	public static final int PUERTO = 3400;
	public static final String SERVIDOR = "localhost";
	public static final String ALGORITMOSIMETRICO = "AES" ;
	public static final String ALGORITMOASIMETRICO = "RSA" ;
	public static final String ALGORITMOHMAC= "HMACSHA1" ;


	public static void main (String args[]) throws IOException
	{
		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;

		try {

			// Crea el socket en el lado cliente
			socket = new Socket(SERVIDOR, PUERTO);
			escritor = new PrintWriter(socket.getOutputStream(),true);
			lector = new BufferedReader( new InputStreamReader(socket.getInputStream()));
			System.out.println("Creando el socket en el lado cliente");

			//Inicia el protocolo de comunicación			
			escritor.println("HOLA");
			System.out.println("Iniciando el protocolo de comunicación	");
			
			//Respuesta del servidor
			String fromServer =lector.readLine();
			if( fromServer == null || !fromServer.equals("OK"))
			{
				throw new Exception("El servidor me está mandando algo diferente a OK me manda: "+ fromServer);
			}
			System.out.println("Recibiendo respuesta del servidor");
			
			//Le mando los tres algoritmos
			escritor.println("ALGORITMOS:AES:RSA:HMACSHA1");
			System.out.println("Enviando algoritmos");

			//Respuesta del servidor
			fromServer = lector.readLine();
			if(fromServer ==null || !fromServer.equals("OK"))
			{
				throw new Exception("El servidor me está mandando algo diferente a OK me manda: "+ fromServer);
			}			
			System.out.println("Recibiendo respuesta del servidor");

			//Envio certificado de cliente
			KeyPair llaves = generarLlaves() ;
			escritor.println(generarCertificado(llaves)); 
			System.out.println("Enviando certificado al servidor");

			//Recibo certificado del servidor
			String strCertificadoServidor = lector.readLine();
			byte[] certificadoServidorBytes = new byte['k'];
			certificadoServidorBytes = DatatypeConverter.parseHexBinary(strCertificadoServidor);
			CertificateFactory creador = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(certificadoServidorBytes);
			X509Certificate certificadoServidor = (X509Certificate)creador.generateCertificate(in);
			System.out.println("Recibiendo certificado del servidor");

			//Genero llave simetrica
			KeyGenerator keygen = KeyGenerator.getInstance(ALGORITMOSIMETRICO);
			SecretKey simetrica = keygen.generateKey() ;
			byte[] llaveSimetrica = simetrica.getEncoded();
			String llaveSimetricaHex = DatatypeConverter.printHexBinary(llaveSimetrica) ;
			System.out.println("Generando llave simetrica");
			
			
			//Envio la llave simetrica
			escritor.println(llaveSimetricaHex);	
			System.out.println("Enviando llave simetrica");
			
			
			//Recibo la llave simetrica
			String simetricaServ = lector.readLine();	
			System.out.println("Recibiendo llave simetrica");
			
			
			//Valido la llave simetrica
			if(llaveSimetricaHex.equals(simetricaServ))
			{
				escritor.println("OK");
			}
			else
			{
				escritor.println("ERROR");
			}
			System.out.println("Validando llave simetrica");
			
			//Envio datos
			String mensaje = "15;41 24.2028,21.04418";
			escritor.println(mensaje);
			System.out.println("Enviando datos primera vez");
			escritor.println(mensaje);
			System.out.println("Enviando datos segunda vez");

			//Recibo la validacion del servidor
			String val = lector.readLine() ;	
			System.out.println("Recibiendo validacion de datos por parte del servidor");
			if (val.equals("ERROR"))
			{
				System.out.println("Esxiste una inconsistencia en los datos recibidos");
				System.out.println("Terminando.");
			}
			else
			{
				System.out.println("Terminando exitosamente.");
			}


		}
		catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}


	}

	private static String generarCertificado( KeyPair llave) throws OperatorCreationException, java.security.cert.CertificateException, CertificateException
	{
		java.security.cert.X509Certificate certificado = gc(llave);
		byte[] certificadoEnBytes = certificado.getEncoded( );
		String certificadoEnString = DatatypeConverter.printHexBinary(certificadoEnBytes);		
		return certificadoEnString ;
	}


	public static java.security.cert.X509Certificate gc(KeyPair keyPair) throws OperatorCreationException, CertificateException, java.security.cert.CertificateException
	{
		Calendar endCalendar = Calendar.getInstance();
		endCalendar.add(1, 10);
		X509v3CertificateBuilder x509v3CertificateBuilder = 
				new X509v3CertificateBuilder(new X500Name("CN=localhost"), 
						BigInteger.valueOf(1L), 
						Calendar.getInstance().getTime(), 
						endCalendar.getTime(), 
						new X500Name("CN=localhost"), 
						SubjectPublicKeyInfo.getInstance(keyPair.getPublic()
								.getEncoded()));
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA")
				.build(keyPair.getPrivate());
		X509CertificateHolder x509CertificateHolder = 
				x509v3CertificateBuilder.build(contentSigner);
		return new JcaX509CertificateConverter().setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()).getCertificate(x509CertificateHolder);
	}



	private static KeyPair generarLlaves()
	{
		KeyPairGenerator generator;
		try {
			generator = KeyPairGenerator.getInstance(ALGORITMOASIMETRICO);
			generator.initialize(1024);

			KeyPair keyPair = generator.generateKeyPair() ;

			return keyPair;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null ;

	}

	

}
