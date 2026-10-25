#!/bin/bash
# Enduriment de sistema CIS/ISO 27001 - Debian 13 (Avaluació i Remeiació Idempotent)

C_OK='\033[1;32m'
C_ERR='\033[1;31m'
C_INF='\033[1;34m'
C_WRN='\033[1;33m'
C_RST='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${C_ERR}Error: L'script requereix privilegis de root.${C_RST}"
  exit 1
fi

echo -e "${C_INF}S'avaluaran i s'aplicaran els següents controls segons l'estàndard CIS/ISO 27001:${C_RST}"
cat << EOF
  - [PKGS-7392]: Actualització de paquets vulnerables
  - [DEB-0810]: Prevenció amb apt-listbugs
  - [PKGS-7370]: Integritat amb debsums
  - [PKGS-7394]: Versions amb apt-show-versions
  - [DEB-0880]: Protecció perimetral Fail2ban
  - [AUTH-9328]: Màscara UMASK 027
  - [AUTH-9230]: Cost computacional contrasenyes (500000 rondes)
  - [DEB-0280]: Aïllament PAM tmpdir
  - [NETW-3200]: Bloqueig protocols dccp, sctp, rds, tipc
  - [KRNL-6000]: Bloqueig ICMP redirects
  - [SSH-7408]: Restriccions OpenSSH
  - [BANN-7126 / BANN-7130]: Banners legals d'accés
  - [ACCT-9622 / ACCT-9626]: Traçabilitat sysstat i acct
  - [FILE-7524]: Sticky Bit en directoris globals
EOF

echo ""
read -p "Estàs d'acord amb aplicar aquests remeis? (s/n): " CONFIRM
if [[ "$CONFIRM" != "s" && "$CONFIRM" != "S" ]]; then
    echo -e "${C_INF}Operació cancel·lada.${C_RST}"
    exit 0
fi
echo ""

C_OK_JA=0
C_OK_APL=0
C_ERRORS=0
LLISTA_ERRORS=()

# --- Funcions generals ---
gestiona_control() {
    local id_control="$1"
    local func_check="$2"
    local func_apply="$3"

    echo -n -e "${C_INF}Avaluant $id_control... ${C_RST}"
    
    if $func_check; then
        echo -e "${C_OK}Estat correcte (Sense canvis).${C_RST}"
        ((C_OK_JA++))
    else
        $func_apply >/dev/null 2>&1
        if $func_check; then
            echo -e "${C_OK}Aplicat i verificat correctament.${C_RST}"
            ((C_OK_APL++))
        else
            echo -e "${C_ERR}ERROR: El control ha fallat durant l'aplicació o verificació.${C_RST}"
            ((C_ERRORS++))
            LLISTA_ERRORS+=("$id_control")
        fi
    fi
}

check_pkg() { dpkg -l | grep -q "^ii  $1 "; }
install_pkg() { DEBIAN_FRONTEND=noninteractive apt-get install -yq "$1"; }

# --- Funcions de verificació i aplicació per control ---

chk_pkgs_7392() { apt-get upgrade -s | grep -q "0 upgraded, 0 newly installed"; }
app_pkgs_7392() { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get upgrade -yq; }

chk_deb_0810() { check_pkg "apt-listbugs"; }
app_deb_0810() { install_pkg "apt-listbugs"; }

chk_pkgs_7370() { check_pkg "debsums"; }
app_pkgs_7370() { install_pkg "debsums"; }

chk_pkgs_7394() { check_pkg "apt-show-versions"; }
app_pkgs_7394() { install_pkg "apt-show-versions"; }

chk_deb_0880() { check_pkg "fail2ban" && systemctl is-active --quiet fail2ban; }
app_deb_0880() { install_pkg "fail2ban" && systemctl enable --now fail2ban; }

chk_auth_9328() {
    grep -q "^UMASK\s*027" /etc/login.defs && \
    grep -q "pam_umask.so" /etc/pam.d/common-session && \
    grep -q "umask 027" /etc/bash.bashrc
}
app_auth_9328() {
    sed -i 's/^UMASK.*/UMASK 027/g' /etc/login.defs
    grep -q "pam_umask.so" /etc/pam.d/common-session || echo "session optional pam_umask.so" >> /etc/pam.d/common-session
    grep -q "umask 027" /etc/bash.bashrc || echo -e "\numask 027" >> /etc/bash.bashrc
}

chk_auth_9230() { grep -q "^SHA_CRYPT_MIN_ROUNDS\s*500000" /etc/login.defs; }
app_auth_9230() {
    if grep -q "SHA_CRYPT_MIN_ROUNDS" /etc/login.defs; then
        sed -i 's/^SHA_CRYPT_MIN_ROUNDS.*/SHA_CRYPT_MIN_ROUNDS 500000/g' /etc/login.defs
    else
        echo "SHA_CRYPT_MIN_ROUNDS 500000" >> /etc/login.defs
    fi
}

chk_deb_0280() { check_pkg "libpam-tmpdir"; }
app_deb_0280() { install_pkg "libpam-tmpdir"; }

chk_netw_3200() { test -f /etc/modprobe.d/cis-protocols.conf && grep -q "dccp" /etc/modprobe.d/cis-protocols.conf; }
app_netw_3200() { echo -e "install dccp /bin/true\ninstall sctp /bin/true\ninstall rds /bin/true\ninstall tipc /bin/true" > /etc/modprobe.d/cis-protocols.conf; }

chk_krnl_6000() { sysctl net.ipv4.conf.all.accept_redirects | grep -q "0" && sysctl net.ipv4.conf.default.accept_redirects | grep -q "0"; }
app_krnl_6000() { echo -e "net.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0" > /etc/sysctl.d/99-cis.conf && sysctl -p /etc/sysctl.d/99-cis.conf; }

chk_ssh_7408() { test -f /etc/ssh/sshd_config.d/99-hardening.conf && grep -q "AllowTcpForwarding no" /etc/ssh/sshd_config.d/99-hardening.conf; }
app_ssh_7408() { echo -e "AllowTcpForwarding no\nX11Forwarding no\nAllowAgentForwarding no\nMaxAuthTries 3" > /etc/ssh/sshd_config.d/99-hardening.conf && systemctl reload ssh; }

chk_bann_7126() { test -s /etc/issue.net && test -f /etc/ssh/sshd_config.d/98-banner.conf; }
app_bann_7126() { echo "Accés restringit. Tota activitat està sent monitoritzada." > /etc/issue.net && echo "Banner /etc/issue.net" > /etc/ssh/sshd_config.d/98-banner.conf && systemctl reload ssh; }

chk_acct_9622() { check_pkg "sysstat" && check_pkg "acct" && systemctl is-active --quiet sysstat && systemctl is-active --quiet acct; }
app_acct_9622() { install_pkg "sysstat" && install_pkg "acct" && systemctl enable --now sysstat acct; }

chk_file_7524() { [ -z "$(find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null)" ]; }
app_file_7524() { find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -exec chmod a+t {} + 2>/dev/null; }

# --- Execució dels controls ---
gestiona_control "Control [PKGS-7392]" chk_pkgs_7392 app_pkgs_7392
gestiona_control "Control [DEB-0810]" chk_deb_0810 app_deb_0810
gestiona_control "Control [PKGS-7370]" chk_pkgs_7370 app_pkgs_7370
gestiona_control "Control [PKGS-7394]" chk_pkgs_7394 app_pkgs_7394
gestiona_control "Control [DEB-0880]" chk_deb_0880 app_deb_0880
gestiona_control "Control [AUTH-9328]" chk_auth_9328 app_auth_9328
gestiona_control "Control [AUTH-9230]" chk_auth_9230 app_auth_9230
gestiona_control "Control [DEB-0280]" chk_deb_0280 app_deb_0280
gestiona_control "Control [NETW-3200]" chk_netw_3200 app_netw_3200
gestiona_control "Control [KRNL-6000]" chk_krnl_6000 app_krnl_6000
gestiona_control "Control [SSH-7408]" chk_ssh_7408 app_ssh_7408
gestiona_control "Controls [BANN-7126 / BANN-7130]" chk_bann_7126 app_bann_7126
gestiona_control "Controls [ACCT-9622 / ACCT-9626]" chk_acct_9622 app_acct_9622
gestiona_control "Control [FILE-7524]" chk_file_7524 app_file_7524

echo ""
echo -e "${C_INF}=================================================${C_RST}"
if [ "$C_ERRORS" -eq 0 ]; then
    echo -e "${C_OK}COMPROVACIÓ FINAL: Operació completada amb èxit.${C_RST}"
    echo -e "${C_OK}Resum: $C_OK_JA ja complien, $C_OK_APL aplicats de nou, 0 errors.${C_RST}"
else
    echo -e "${C_ERR}COMPROVACIÓ FINAL: L'auditoria detecta $C_ERRORS errors estructurals.${C_RST}"
    echo -e "${C_WRN}Resum: $C_OK_JA ja complien, $C_OK_APL aplicats, $C_ERRORS fallades.${C_RST}"
    echo -e "${C_ERR}Els següents controls requereixen atenció manual d'administració:${C_RST}"
    for err in "${LLISTA_ERRORS[@]}"; do
        echo -e "  - ${C_ERR}$err${C_RST}"
    done
fi
echo -e "${C_INF}=================================================${C_RST}"
