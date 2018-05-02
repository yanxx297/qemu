# Default configuration for x86_64-softmmu

include pci.mak
include sound.mak
include usb.mak
CONFIG_QXL=$(CONFIG_SPICE)
CONFIG_VGA_ISA=y
CONFIG_VGA_CIRRUS=y
CONFIG_VMWARE_VGA=y
CONFIG_VMXNET3_PCI=y
CONFIG_VIRTIO_VGA=y
CONFIG_VMMOUSE=y
CONFIG_IPMI=y
CONFIG_IPMI_LOCAL=y
CONFIG_IPMI_EXTERN=y
CONFIG_ISA_IPMI_KCS=y
CONFIG_ISA_IPMI_BT=y
CONFIG_SERIAL=y
CONFIG_SERIAL_ISA=y
CONFIG_PARALLEL=y
CONFIG_I8254=y
CONFIG_PCSPK=y
CONFIG_PCKBD=y
CONFIG_FDC=y
CONFIG_ACPI=y
CONFIG_ACPI_X86=y
CONFIG_ACPI_X86_ICH=y
CONFIG_ACPI_MEMORY_HOTPLUG=y
CONFIG_ACPI_CPU_HOTPLUG=y
CONFIG_APM=y
CONFIG_I8257=y
CONFIG_IDE_ISA=y
CONFIG_IDE_PIIX=y
CONFIG_NE2000_ISA=y
CONFIG_HPET=y
CONFIG_APPLESMC=y
CONFIG_I8259=y
CONFIG_PFLASH_CFI01=y
CONFIG_TPM_TIS=$(CONFIG_TPM)
CONFIG_MC146818RTC=y
CONFIG_PCI_PIIX=y
CONFIG_WDT_IB700=y
CONFIG_ISA_DEBUG=y
CONFIG_ISA_TESTDEV=y
CONFIG_VMPORT=y
CONFIG_SGA=y
CONFIG_LPC_ICH9=y
CONFIG_PCI_Q35=y
CONFIG_APIC=y
CONFIG_IOAPIC=y
CONFIG_PVPANIC=y
CONFIG_MEM_HOTPLUG=y
CONFIG_NVDIMM=y
CONFIG_ACPI_NVDIMM=y
CONFIG_PCIE_PORT=y
CONFIG_XIO3130=y
CONFIG_IOH3420=y
CONFIG_I82801B11=y
CONFIG_SMBIOS=y
CONFIG_HYPERV_TESTDEV=$(CONFIG_KVM)
CONFIG_PXB=y
CONFIG_ACPI_VMGENID=y
