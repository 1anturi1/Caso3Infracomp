package clientes;

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
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Calendar;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.cert.X509Certificate;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

//importar task
import uniandes.gload.core.Task;
public class ClienteS extends Task
{
	/**
	 * Puerto
	 */
	public static final int PUERTO = 8080;
	/**
	 * Servidor
	 */
	public static final String SERVIDOR = "localhost";
	/**
	 * Llaves
	 */
	private static java.security.KeyPair llavesCliente;

	public void execute()
	{
		llavesCliente = generarLlaves();

		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;
		try {

			// Crea el socket en el lado cliente
			socket = new Socket(SERVIDOR, PUERTO);
			escritor = new PrintWriter(socket.getOutputStream(),true);
			lector = new BufferedReader( new InputStreamReader(socket.getInputStream()));
			procesar(lector, escritor);
			escritor.close();
			lector.close();
			socket.close();
		}
		catch (IOException e) {
			e.printStackTrace();
			System.exit(-1);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {

			
			escritor.close();
			lector.close();
			socket.close();
			
			
		}
		catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}


	}

	/**
	 * Se encarga de crear el certificado del cliente
	 * @param llave par de llaves 
	 * @return Certificado en String
	 * @throws OperatorCreationException
	 * @throws java.security.cert.CertificateException
	 * @throws CertificateException
	 */
	private static String generarCertificado( KeyPair llave) throws OperatorCreationException, java.security.cert.CertificateException, CertificateException
	{
		java.security.cert.X509Certificate certificado = generarCertificado2(llave);
		byte[] certificadoEnBytes = certificado.getEncoded( );
		String certificadoEnString = aHexaString(certificadoEnBytes);		
		return certificadoEnString ;
	}
	
	/**
	 * Genera las llaves para hacer el cifrado asimétrico
	 * @return par de llaves del cliente
	 */
	public static KeyPair generarLlaves () 
	{
		KeyPairGenerator kpGen;
		try {
			kpGen = KeyPairGenerator.getInstance("RSA");
			kpGen.initialize(1024, new SecureRandom());
			return kpGen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;

	}
	
	public static void procesar (BufferedReader lector, PrintWriter escritor) throws Exception
	{
		//--------------------------------------------------------
		//  Enviando "HOLA"
		//--------------------------------------------------------
		// Crea el socket en el lado cliente
		
				
		System.out.println("Iniciando el protocolo de comunicación	");
		escritor.println("HOLA");
		
		//-------------------------------------------------------
		// Recibir "OK"
		//-------------------------------------------------------
		
		System.out.println("Recibiendo respuesta del servidor");
		String fromServer =lector.readLine();
		if( fromServer == null || !fromServer.equals("OK"))
		{
			throw new Exception("El servidor me está mandando algo diferente a OK me manda: "+ fromServer);
		}

		//-----------------------------------------------------------------
		// Le mando los 3 algoritmos necesarios para el funcionamiento
		//-----------------------------------------------------------------
		//Le mando los tres algoritmos
		
		System.out.println("Enviando algoritmos");
		escritor.println("ALGORITMOS:AES:RSA:HMACSHA1");

		//-----------------------------------------------------------------
		// Recibo el "OK"
		//-----------------------------------------------------------------
		
		System.out.println("Recibiendo respuesta del servidor");
		fromServer = lector.readLine();
		if(fromServer ==null || !fromServer.equals("OK"))
		{
			throw new Exception("El servidor me está mandando algo diferente a OK me manda: "+ fromServer);
		}
		
		//-----------------------------------------------------------------
		// Generar y envíar el certificado
		//-----------------------------------------------------------------
		
		System.out.println("Enviando certificado al servidor");
		String certificadoEnString = generarCertificado(llavesCliente);
		escritor.println(certificadoEnString);

		//-----------------------------------------------------------------
		// Recibir y procesar el certificado del servidor
		//-----------------------------------------------------------------
		
		System.out.println("Recibiendo certificado del servidor");
		String strCertificadoServidor = lector.readLine();
		byte[] certificadoServidorBytes = new byte['K'];
		certificadoServidorBytes = aArregloBytes(strCertificadoServidor);
		CertificateFactory creador = CertificateFactory.getInstance("X.509");
		InputStream in = new ByteArrayInputStream(certificadoServidorBytes);
		X509Certificate certificadoServidor = (X509Certificate)creador.generateCertificate(in);

		//-----------------------------------------------------------------
		//Creación y envío de la llave simétrica
		//-----------------------------------------------------------------
		System.out.println("Generando llave simetrica");
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		SecretKey simetrica = keygen.generateKey();
		byte[] ciphertext1 = cifrar(simetrica.getEncoded(),certificadoServidor.getPublicKey(), "RSA");
		
		System.out.println("Enviando llave simetrica");
		escritor.println(aHexaString(ciphertext1));
		
		//------------------------------------------------------------------
		// Comparo la llave que me llega por la que ya tengo. 
		//-----------------------------------------------------------------
		System.out.println("Recibiendo llave simetrica");
		String linea = lector.readLine();
		System.out.println(linea);
		byte[] llaveSimetrica = descifrar( aArregloBytes(linea), 
		        llavesCliente.getPrivate(), "RSA");
		
		System.out.println("Validando llave simetrica");
		SecretKey simetrica1 = new SecretKeySpec(llaveSimetrica, 0, llaveSimetrica.length, "AES");
		if (!simetrica.equals(simetrica1)) 
		{
			escritor.println("ERROR");
			throw new Exception("Las llaves simétricas no coinciden");
		}
		System.out.println("Llave simetrica validada, enviando "+"OK");
		escritor.println("OK");
		
		//-----------------------------------------------------------------
		// Envío de datos
		//----------------------------------------------------------------
		System.out.println("Enviando datos cifrados por la llave simétrica");
		String mensaje = "15;44.228,21.18";
		byte[] bMensaje = mensaje.getBytes();
		String datosCifrado = aHexaString(cifrarSimetrico(bMensaje, simetrica, "AES"));
		escritor.println(datosCifrado);
		
		
		//-----------------------------------------------------------------
		// Creación y envío de HMAC
		//-----------------------------------------------------------------
		System.out.println("Enviando HMAC");
		byte[] HMAC = HMAC(bMensaje, simetrica, "HMACSHA1");
		escritor.println(aHexaString(HMAC));
		
		//-----------------------------------------------------------------
		// Validación de datos reenviados por el servidor
		//-----------------------------------------------------------------
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
	/**
	 * Método auxiliar para crear el certificado
	 * @param llaves llaves del cliente X509Certificate
	 * @return Certificado en formato
	 * @throws OperatorCreationException
	 * @throws CertificateException
	 */
	public static X509Certificate generarCertificado2(KeyPair llaves) throws OperatorCreationException, CertificateException
	{
		Calendar endCalendar = Calendar.getInstance();
		endCalendar.add(1, 10);
		X509v3CertificateBuilder x509v3CertificateBuilder = 
				new X509v3CertificateBuilder(new X500Name("CN=localhost"), 
						BigInteger.valueOf(1L), 
						Calendar.getInstance().getTime(), 
						endCalendar.getTime(), 
						new X500Name("CN=localhost"), 
						SubjectPublicKeyInfo.getInstance(llaves.getPublic()
								.getEncoded()));
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA")
				.build(llaves.getPrivate());
		X509CertificateHolder x509CertificateHolder = 
				x509v3CertificateBuilder.build(contentSigner);
		return new JcaX509CertificateConverter().setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()).getCertificate(x509CertificateHolder);
	}
	//----------------------------------------------------------------
	// Método HMAC
	//----------------------------------------------------------------
	
	public static byte[] HMAC(byte[] mensaje, Key llave, String metodo) throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, UnsupportedEncodingException
	  {
	    Mac mac = Mac.getInstance(metodo);
	    mac.init(llave);
	    byte[] bytes = mac.doFinal(mensaje);
	    return bytes;
	  }
	
	//----------------------------------------------------------------
	//Métodos para cifrar y descifrar
	//---------------------------------------------------------------

	public static byte[] cifrarSimetrico(byte[] mensaje, Key llave, String metodo) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
	  {
	    metodo = metodo + "/ECB/PKCS5Padding";
	    Cipher decifrador = Cipher.getInstance(metodo);
	    decifrador.init(1, llave);
	    return decifrador.doFinal(mensaje);
	  }
	
	public static byte[] cifrar(byte[] mensaje, Key llave, String metodo)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
	{
		Cipher decifrador = Cipher.getInstance(metodo);
		decifrador.init(1, llave);
		return decifrador.doFinal(mensaje);
	}

	public static byte[] descifrar(byte[] mensaje, Key llave, String metodo)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		
		Cipher decifrador = Cipher.getInstance(metodo);
		decifrador.init(Cipher.DECRYPT_MODE, llave);
		return decifrador.doFinal(mensaje);
	}
	//----------------------------------------------------------------
	//Métodos para para el cambio a hexa
	//---------------------------------------------------------------
	public static String aHexaString(byte[] arreglo) {
		return DatatypeConverter.printHexBinary(arreglo);
	}

	public static byte[] aArregloBytes(String s) {
		return DatatypeConverter.parseHexBinary(s);
	}
	//---------------------------------------------------
	// Métodos de de Gload
	//---------------------------------------------------
	@Override
	public void fail() {
		System.out.println(Task.MENSAJE_FAIL);
	}

	@Override
	public void success() {
		System.out.println(Task.OK_MESSAGE);
	}

}
