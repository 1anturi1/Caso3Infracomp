package srvSinSeg;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors ;
import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.MBeanServer;
import javax.management.ObjectName;

import srvSinSeg.Monitor;



public class C {
	private static ServerSocket ss;	
	private static final String MAESTRO = "MAESTRO SIN SEGURIDAD: ";
	private static X509Certificate certSer; /* acceso default */
	private static KeyPair keyPairServidor; /* acceso default */

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception{
		// TODO Auto-generated method stub


		System.out.println(MAESTRO + "Establezca puerto de conexion:");
		InputStreamReader isr = new InputStreamReader(System.in);
		BufferedReader br = new BufferedReader(isr);
		int ip = Integer.parseInt(br.readLine());
		System.out.println(MAESTRO + "Empezando servidor maestro en puerto " + ip);
		// Adiciona la libreria como un proveedor de seguridad.
		// Necesario para crear llaves.
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());		
		// Código para hacer las pruebas
		System.out.println(MAESTRO + "Establezca el numero de prueba");
		InputStreamReader isr2 = new InputStreamReader(System.in);
		BufferedReader br2 = new BufferedReader(isr2);
		String nPrueba = br2.readLine();
		System.out.println(nPrueba);
		//----------------------------------------

		int idThread = 0;
		// Crea el socket que escucha en el puerto seleccionado.
		ss = new ServerSocket(ip);
		System.out.println(MAESTRO + "Socket creado.");

		keyPairServidor = S.grsa();
		certSer = S.gc(keyPairServidor);
		D.initCertificate(certSer, keyPairServidor);

		// Selección de threads
		ExecutorService ex = Executors.newFixedThreadPool(2) ;
		Monitor monitor = new Monitor(nPrueba);
		boolean empece = false;

		while (true) {
			try { 
				Socket sc = ss.accept();				
				if(!empece)
				{
					monitor.start();
					empece = true ;
				}				
				System.out.println(MAESTRO + "Cliente " + idThread + " aceptado.");				
				ex.execute( new D(sc,idThread, nPrueba)) ;	
				idThread++;
			} catch (IOException e) {
				System.out.println(MAESTRO + "Error creando el socket cliente.");
				e.printStackTrace();
			}
		}
	}

	//	public double getSystemCpuLoad() throws Exception {
	//		MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
	//		ObjectName name = ObjectName.getInstance("java.lang:type=OperatingSystem");
	//		AttributeList list = mbs.getAttributes(name, new String[]{ "SystemCpuLoad" });
	//		if (list.isEmpty()) return Double.NaN;
	//		Attribute att = (Attribute)list.get(0);
	//		Double value = (Double)att.getValue();
	//		// usually takes a couple of seconds before we get real values
	//		if (value == -1.0) return Double.NaN;
	//		// returns a percentage value with 1 decimal point precision
	//		return ((int)(value * 1000) / 10.0);
	//	}

}
