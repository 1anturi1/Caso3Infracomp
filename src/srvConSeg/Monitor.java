package srvConSeg;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.management.ManagementFactory;

import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.MBeanServer;
import javax.management.ObjectName;

public class Monitor extends Thread{

	BufferedWriter log = null;
	
	
	public Monitor(String nPrueba) throws IOException {
		this.log = new BufferedWriter(new FileWriter("E1CPU"+nPrueba+".csv",false));
	}
	public void run() {
		
		try {
			while(true) {
				log.newLine();
				log.write(getSystemCpuLoad()+";"+System.nanoTime());
				log.flush();
				Thread.sleep(67);
			}
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public double getSystemCpuLoad() throws Exception {
		 MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
		 ObjectName name = ObjectName.getInstance("java.lang:type=OperatingSystem");
		 AttributeList list = mbs.getAttributes(name, new String[]{ "SystemCpuLoad" });
		 if (list.isEmpty()) return Double.NaN;
		 Attribute att = (Attribute)list.get(0);
		 Double value = (Double)att.getValue();
		 // usually takes a couple of seconds before we get real values
		 if (value == -1.0) return Double.NaN;
		 // returns a percentage value with 1 decimal point precision
		 return ((int)(value * 1000) / 10.0);
		 }
}