package clientes;
import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class GeneradorClienteS 
{
	private LoadGenerator generator;

	public GeneradorClienteS()
	{
		Task work = createTask();
		int numberofTasks = 20;
		int gapBetweenTasks = 20;
		generator = new LoadGenerator("Client - Server Load Test", numberofTasks, work, gapBetweenTasks);
		generator.generate();

	}

	private Task createTask() {
		return new ClienteS();
	}

	public static void main(String[] args) {
		@SuppressWarnings("unused")
		GeneradorClienteS gen = new GeneradorClienteS();

	}

}
