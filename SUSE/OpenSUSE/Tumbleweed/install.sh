#!/bin/bash

PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/opt/mellanox/scripts"
NIC_FW_UPDATE_DONE=0

fspath=$(readlink -f `dirname $0`)

rshimlog=`which bfrshlog 2> /dev/null`
log()
{
	msg="[$(date +%H:%M:%S)] $*"
	echo "$msg" > /dev/ttyAMA0
	echo "$msg" > /dev/hvc0
	if [ -n "$rshimlog" ]; then
		$rshimlog "$*"
	fi
}

bind_partitions()
{
	mount --bind /proc /mnt/proc
	mount --bind /dev /mnt/dev
	mount --bind /sys /mnt/sys
}

unmount_partitions()
{
	umount /mnt/sys/fs/fuse/connections > /dev/null 2>&1 || true
	umount /mnt/sys > /dev/null 2>&1
	umount /mnt/dev > /dev/null 2>&1
	umount /mnt/proc > /dev/null 2>&1
	umount /mnt/boot/efi > /dev/null 2>&1
	umount /mnt > /dev/null 2>&1
}

#
# Set the Hardware Clock from the System Clock
#

hwclock -w

distro="Tumbleweed"

function_exists()
{
	declare -f -F "$1" > /dev/null
	return $?
}

DHCP_CLASS_ID=${PXE_DHCP_CLASS_ID:-""}
DHCP_CLASS_ID_OOB=${DHCP_CLASS_ID_OOB:-"NVIDIA/BF/OOB"}
DHCP_CLASS_ID_DP=${DHCP_CLASS_ID_DP:-"NVIDIA/BF/DP"}
FACTORY_DEFAULT_DHCP_BEHAVIOR=${FACTORY_DEFAULT_DHCP_BEHAVIOR:-"true"}

if [ "${FACTORY_DEFAULT_DHCP_BEHAVIOR}" == "true" ]; then
	# Set factory defaults
	DHCP_CLASS_ID="NVIDIA/BF/PXE"
	DHCP_CLASS_ID_OOB="NVIDIA/BF/OOB"
	DHCP_CLASS_ID_DP="NVIDIA/BF/DP"
fi

log "INFO: $distro installation started"

device=/dev/mmcblk0

#qemu test
#device=/dev/vda

dd if=/dev/zero of=$device bs=512 count=1

parted --script $device -- \
		mklabel gpt \
		mkpart primary 1MiB 201MiB set 1 esp on \
		mkpart primary 201MiB 100%

sync
partprobe "$device" > /dev/null 2>&1
sleep 1
blockdev --rereadpt "$device" > /dev/null 2>&1

# Generate some entropy
mke2fs ${device}p2 >> /dev/null

# Copy the kernel image
mkdosfs ${device}p1 -n system-boot
mkfs.btrfs -f ${device}p2 -L rootfs
#mkfs.xfs -f ${device}2 -L rootfs

fsck.vfat -a ${device}p1

root=${device/\/dev\/}p2
mount ${device}p2 /mnt
mkdir -p /mnt/boot
mkdir -p /mnt/boot/efi
mount ${device}p1 /mnt/boot/efi

echo "Extracting ..."
export EXTRACT_UNSAFE_SYMLINKS=1
tar Jxf $fspath/image.tar.xz --warning=no-timestamp -C /mnt
sync

cat > /mnt/etc/fstab << EOF
#
# /etc/fstab
#
#
${device}p2  /           btrfs   defaults                   0 1
${device}p1  /boot/efi   vfat    umask=0077,shortname=winnt 0 2
EOF

cat > /mnt/etc/udev/rules.d/50-dev-root.rules << EOF
# If the system was booted without an initramfs, grubby
# will look for the symbolic link "/dev/root" to figure
# out the root file system block device.
SUBSYSTEM=="block", KERNEL=="$root", SYMLINK+="root"
EOF

# Update default.bfb
bfb_location=/lib/firmware/mellanox/default.bfb

if [ -f "$bfb_location" ]; then
	/bin/rm -f /mnt/lib/firmware/mellanox/boot/default.bfb
	cp $bfb_location /mnt/lib/firmware/mellanox/boot/default.bfb
fi

chmod 600 /mnt/etc/ssh/*

# Disable Firewall services
/bin/rm -f /mnt/etc/systemd/system/multi-user.target.wants/firewalld.service
/bin/rm -f /mnt/etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service

bind_partitions

# Then, set boot arguments: Read current 'console' and 'earlycon'
# parameters, and append the root filesystem parameters.
bootarg="$(cat /proc/cmdline | sed 's/initrd=initramfs//;s/console=.*//')"

sed -i -e "s@GRUB_CMDLINE_LINUX=.*@GRUB_CMDLINE_LINUX=\"crashkernel=auto $bootarg console=tty0 console=hvc0 console=ttyAMA0 earlycon=pl011,0x01000000 modprobe.blacklist=mlx5_core,mlx5_ib net.ifnames=0 biosdevname=0 iommu.passthrough=1\"@" /mnt/etc/default/grub

#qemu test
#sed -i -e "s@GRUB_CMDLINE_LINUX=.*@GRUB_CMDLINE_LINUX=\"crashkernel=auto $bootarg console=tty0 console=hvc0 modprobe.blacklist=mlx5_core,mlx5_ib net.ifnames=0 biosdevname=0 iommu.passthrough=1\"@" /mnt/etc/default/grub

if (hexdump -C /sys/firmware/acpi/tables/SSDT* | grep -q MLNXBF33); then
    # BlueField-3
    sed -i -e "s/0x01000000/0x13010000/g" /mnt/etc/default/grub
fi

mkdir -p /mnt/boot/efi/EFI
mkdir -p /mnt/boot/efi/EFI/opensuse
chroot /mnt mount -t efivarfs none /sys/firmware/efi/efivars
chroot /mnt grub2-mkconfig -o /boot/grub2/grub.cfg
chroot /mnt grub2-install /dev/${device}p1

kdir=$(/bin/ls -1d /mnt/lib/modules/6.* 2> /dev/null)
kver=""
if [ -n "$kdir" ]; then
    kver=${kdir##*/}
    DRACUT_CMD=`chroot /mnt /bin/ls -1 /sbin/dracut /usr/bin/dracut 2> /dev/null | head -n 1 | tr -d '\n'`
    chroot /mnt grub2-set-default 0
    chroot /mnt $DRACUT_CMD --kver ${kver} --force --add-drivers "mlxbf-bootctl sdhci-of-dwcmshc mlxbf_tmfifo dw_mmc-bluefield mmc_block virtio_console mlx5_core mlx5_ib ib_umad nvme nvme-tcp nvme-rdma nvme-fc nvme-fabrics nvme-core ext4 virtio_blk virtio_balloon virtio_vdpa virtio_scsi virtio_blk vfat msdos fat exfat nls_cp437 nls_cp850 nls_iso8859-1 efivarfs" /boot/initrd-${kver}
else
    kver=$(/bin/ls -1 /mnt/lib/modules/ | head -1)
fi

if [ `wc -l /mnt/etc/hostname | cut -d ' ' -f 1` -eq 0 ]; then
	echo "localhost" > /mnt/etc/hostname
fi

cat > /mnt/etc/resolv.conf << EOF
nameserver 192.168.100.1
nameserver 8.8.8.8
EOF

cat > /mnt/etc/NetworkManager/system-connections/tmfifo-net.nmconnection << EOF
[connection]
id=tmfifo
uuid=f312b57f-72c6-4862-985a-48d997ba31b9
type=ethernet
interface-name=eth0
autoconnect=true

[ethernet]

[ipv4]
method=auto

[ipv6]
addr-gen-mode=default
method=auto

[proxy]
EOF

chmod 600 /mnt/etc/NetworkManager/system-connections/tmfifo-net.nmconnection

chroot /mnt /bin/systemctl enable serial-getty@ttyAMA0.service
chroot /mnt /bin/systemctl enable serial-getty@ttyAMA1.service
chroot /mnt /bin/systemctl enable serial-getty@hvc0.service

chroot /mnt /bin/systemctl enable sshd.service
chroot /mnt /bin/systemctl enable NetworkManager.service
chroot /mnt /bin/systemctl enable systemd-resolved.service
chroot /mnt /bin/systemctl enable systemd-networkd.service

chroot /mnt echo 'root:$6$JvMP7NN2kMstrskY$bHT2jCClGqMW.1qtsocFy66trPwwVIgCEi/gEBJC9gLkdspWIahwHcmll3kwFFkPFSHHt076pj0.yEdWvGQN90' > pass.txt
chroot /mnt chpasswd -e < pass.txt
chroot /mnt rm -rf pass.txt

sync

chroot /mnt umount /sys/firmware/efi/efivars
chroot /mnt umount /boot/efi
umount /mnt/sys
umount /mnt/dev
umount /mnt/proc
umount /mnt
sync

#bfbootmgr --cleanall > /dev/null 2>&1

log "INFO: Installation finished"
sleep 3
log "INFO: Rebooting..."
# Wait for these messages to be pulled by the rshim service
sleep 3
