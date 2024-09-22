#include <ntifs.h>

extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName,
		PDRIVER_INITIALIZE InitializationFunction);

	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress,
		PEPROCESS TargetProcess, PVOID TargetAddress,
		SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize);
}

void debug_print(PCSTR text) {
#ifndef DEBUG
	UNREFERENCED_PARAMETER(text);
#endif   // DEBUG

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
}

namespace driver {	
	namespace codes {
		// SERÁ USADO PARA INJETAR O DRIVER.
		constexpr ULONG attach =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		// LER PROCESSOS DA MEMÓRIA.
		constexpr ULONG read =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		// ESCREVER OS PROCESSOS DA MEMÓRIA.
		constexpr ULONG write =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	} // namespace CODES

	// COMPARTILHADO ENTRE USER MODE & KERNEL MODE.
	struct Request {
		HANDLE process_id;

		PVOID target;
		PVOID buffer;

		SIZE_T size;
		SIZE_T return_size;
	};

	NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	// NOTA: PARA FAZER.
	NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);

		debug_print("[+] Controle de driver chamado.\n");

		NTSTATUS status = STATUS_UNSUCCESSFUL;

		// PRECISAMOS DISSO PARA SABER QUAIS CÓDIGOS PASSARAM POR.
		PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);

		// IRÁ ACESSAR OBJECT REQUEST ENVIADO PELO USER MODE.
		auto request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);

		if (stack_irp == nullptr || request == nullptr) {
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}

		// TARGET PROCESS QUE IREMOS QUERER ACESSAR.
		static PEPROCESS target_process = nullptr;

		const ULONG control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;
		switch (control_code) {
			case codes::attach:
				status = PsLookupProcessByProcessId(request->process_id, &target_process);
				break;

			case codes::read:
				if (target_process != nullptr)
					status = MmCopyVirtualMemory(target_process, request->target,
						PsGetCurrentProcess(), request->buffer,
						request->size, KernelMode, &request->return_size);

				break;

			case codes::write:
				if (target_process != nullptr)
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), request->buffer,
						target_process, request->target,
						request->size, KernelMode, &request->return_size);

				break;

			default:
				break;
		}

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof(Request);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return status;
	}

}

// VERDADEIRO PONTO DE ENTRADA.
NTSTATUS driver_main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
		UNREFERENCED_PARAMETER(registry_path);

		UNICODE_STRING device_name = {};
		RtlInitUnicodeString(&device_name, L"\\Device\\PedroDriver");

		// CRIA O DRIVER OBJECT.
		PDEVICE_OBJECT device_object = nullptr;
		NTSTATUS status = IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN,
			FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);
		if (status != STATUS_SUCCESS) {
			debug_print("[-]Erro ao criar dispositivo de driver.\n");
			return status;
		}

		debug_print("[+] Dispositivo de driver criado com sucesso.\n");

		UNICODE_STRING symbolic_link = {};
		RtlInitUnicodeString(&symbolic_link, L"\\DosDevices\\PedroDriver");

		status = IoCreateSymbolicLink(&symbolic_link, &device_name);
		if (status != STATUS_SUCCESS) {
			debug_print("[-] Erro ao estabelecer symbolic link.\n");
		}

		debug_print("[+] Driver symbolic link inicializado com sucesso.\n");

		// PERMITIRÁ ENVIAR PEQUENAS QUANTIDADES DE DATA ENTRE PEDRODRIVER/PEDRO.
		SetFlag(device_object->Flags, DO_BUFFERED_IO);

		// SETARÁ OS HANDLERS DO DRIVER PARA AS FUNÇÕES COM A LÓGICA.
		driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;
		driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;
		driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;
		
		ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);

		debug_print("[+] Driver inicializado com sucesso.\n");

		return status;
	}

// KDMAPPER VAI CHAMAR ESSE BLOCO COMO "PONTO DE ENTRADA", MAS SEUS PARÂMETROS SERÃO NULOS.
NTSTATUS DriverEntry() {
	debug_print("[+] Pedroca's Driver no kernel!\n");

	UNICODE_STRING driver_name = {};
	RtlInitUnicodeString(&driver_name, L"\\Driver\\PedroDriver");

	return IoCreateDriver(&driver_name, &driver_main);
}