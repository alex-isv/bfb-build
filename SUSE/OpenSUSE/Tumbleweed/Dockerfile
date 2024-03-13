from opensuse/tumbleweed

WORKDIR /root/workspace

ADD create_bfb .
ADD install.sh .
ADD bootimages bootimages/
ADD qemu-aarch64-static /usr/bin/

RUN zypper ref

RUN zypper --non-interactive in grub2-arm64-efi grub2-arm64-efi-extras grub2-branding-openSUSE
RUN zypper --non-interactive in kernel-default
RUN zypper --non-interactive in dhcp-client
RUN zypper --non-interactive in parted wget dosfstools
RUN zypper --non-interactive in dracut-tools dracut-kiwi-lib dracut-kiwi-oem-dump dracut-sshd
RUN zypper --non-interactive in usbutils pciutils binutils
RUN zypper --non-interactive in shim sudo which openssh openssh-server-config-rootlogin vim
RUN zypper --non-interactive in systemd-network ethtool ethtool-bash-completion
RUN zypper --non-interactive in NetworkManager
RUN /usr/bin/dracut -f --regenerate-all

#RUN zypper --non-interactive in wicked wicked-service
#RUN zypper --non-interactive mstflint

RUN rpm -ihv --force /root/workspace/bootimages/mlxbf-bootimages-*.aarch64.rpm || true
RUN rpm -ivh --nodeps /root/workspace/bootimages/mlxbf-bfscripts-*.noarch.rpm || true
#RUN /root/workspace/create_bfb
CMD /root/workspace/create_bfb
