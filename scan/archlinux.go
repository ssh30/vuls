/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package scan

import (
	"fmt"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// inherit OsTypeInterface
type archlinux struct {
	base
}

// NewArchLinux  constructor
func newArchLinux(c config.ServerInfo) *archlinux {
	d := &archlinux{
		base: base{
			osPackages: osPackages{
				Packages:  models.Packages{},
				VulnInfos: models.VulnInfos{},
			},
		},
	}
	d.log = util.NewCustomLogger(c)
	d.setServerInfo(c)
	return d
}

//https://github.com/mizzy/specinfra/blob/master/lib/specinfra/helper/detect_os/arch.rb
func detectArchLinux(c config.ServerInfo) (itsMe bool, archlinux osTypeInterface) {
	archlinux = newArchLinux(c)

	// Prevent from adding `set -o pipefail` option
	c.Distro = config.Distro{Family: config.ArchLinux}

	if r := exec(c, "ls /etc/arch-release", noSudo); r.isSuccess() {
		if b := exec(c, "head -n 1  /etc/arch-release | awk '{print $1\" \"$2}'", noSudo); b.isSuccess() {
			rel := strings.TrimSpace(b.Stdout)
			archlinux.setDistro(config.ArchLinux, rel)
			return true, archlinux
		}
	}
	util.Log.Debugf("Not ArchLinux. servername: %s", c.ServerName)
	return false, archlinux
}

func (o *archlinux) checkIfSudoNoPasswd() error {
	// on arch we can run arch-audit with regular priviledges
	o.log.Infof("sudo ... No need")
	return nil
}

func (o *archlinux) checkDependencies() error {
	packNames := []string{}
	packNames = append(packNames, "arch-audit")

	o.log.Infof("Dependencies... we need arch-audit")

	for _, name := range packNames {
		cmd := "pacman -Qs " + name
		if r := o.exec(cmd, noSudo); !r.isSuccess() {
			msg := fmt.Sprintf("%s is not installed", name)
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}
	}
	o.log.Infof("Dependencies... Pass")
	return nil
}

func (o *archlinux) scanPackages() error {
	// collect the running kernel information
	release, version, err := o.runningKernel()
	if err != nil {
		o.log.Errorf("Failed to scan the running kernel version: %s", err)
		return err
	}
	o.Kernel = models.Kernel{
		Release: release,
		Version: version,
	}

	rebootRequired, err := o.rebootRequired()
	if err != nil {
		o.log.Errorf("Failed to detect the kernel reboot required: %s", err)
		return err
	}
	o.Kernel.RebootRequired = rebootRequired

	packs, err := o.scanInstalledPackages()
	if err != nil {
		o.log.Errorf("Failed to scan installed packages: %s", err)
		return err
	}
	o.Packages = packs

	unsecures, err := o.scanUnsecurePackages()
	if err != nil {
		o.log.Errorf("Failed to scan vulnerable packages: %s", err)
		return err
	}
	o.VulnInfos = unsecures
	return nil
}

func (o *archlinux) rebootRequired() (bool, error) {
	cmd := util.PrependProxyEnv("[[ $(pacman -Q linux | cut -d \" \" -f 2) > $(uname -r) ]] && echo \"reboot\"")

	r := o.exec(cmd, noSudo)
	if r.isSuccess() {
		return false, fmt.Errorf("Failed to SSH: %s", r)
	}
	switch r.ExitStatus {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, fmt.Errorf("Failed to check reboot reauired: %s", r)

	}
}

func (o *archlinux) scanInstalledPackages() (models.Packages, error) {
	cmd := util.PrependProxyEnv("pacman -Q")
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}
	return o.parsePkgVersion(r.Stdout), nil
}

func (o *archlinux) scanUnsecurePackages() (models.VulnInfos, error) {
	cmd := util.PrependProxyEnv("arch-audit -f \" %n %c\"")
	r := o.exec(cmd, noSudo)
	if !r.isSuccess(0, 1) {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}
	if r.ExitStatus == 0 {
		// no vulnerabilities
		return nil, nil
	}

	var packAdtRslt []pkgAuditResult
	blocks := o.splitIntoBlocks(r.Stdout)
	for _, b := range blocks {
		name, cveIDs, _ := o.parseBlock(b)
		if len(cveIDs) == 0 {
			continue
		}
		pack, found := o.Packages[name]
		if !found {
			return nil, fmt.Errorf("Vulnerable package: %s is not found", name)
		}
		packAdtRslt = append(packAdtRslt, pkgAuditResult{
			pack: pack,
			vulnIDCveIDs: vulnIDCveIDs{
				cveIDs: cveIDs,
			},
		})
	}
	cveIDAdtMap := make(map[string][]pkgAuditResult)
	for _, p := range packAdtRslt {
		for _, cid := range p.vulnIDCveIDs.cveIDs {
			cveIDAdtMap[cid] = append(cveIDAdtMap[cid], p)
		}
	}

	vinfos := models.VulnInfos{}
	for cveID := range cveIDAdtMap {
		packs := models.Packages{}
		for _, r := range cveIDAdtMap[cveID] {
			packs[r.pack.Name] = r.pack
		}
		disAdvs := []models.DistroAdvisory{}
		for _, r := range cveIDAdtMap[cveID] {
			disAdvs = append(disAdvs, models.DistroAdvisory{
				AdvisoryID: r.vulnIDCveIDs.vulnID,
			})
		}

		affected := models.PackageStatuses{}
		for name := range packs {
			affected = append(affected, models.PackageStatus{
				Name: name,
			})
		}
		vinfos[cveID] = models.VulnInfo{
			CveID:            cveID,
			AffectedPackages: affected,
			DistroAdvisories: disAdvs,
			Confidence:       models.PkgAuditMatch,
		}
	}

	return vinfos, nil
}

func (o *archlinux) parsePkgVersion(stdout string) models.Packages {
	packs := models.Packages{}
	lines := strings.Split(stdout, "\n")
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) < 2 {
			continue
		}

		packVer := fields[0]
		splitted := strings.Split(packVer, "-")
		ver := splitted[len(splitted)-1]
		name := strings.Join(splitted[:len(splitted)-1], "-")

		switch fields[1] {
		case "?", "=":
			packs[name] = models.Package{
				Name:    name,
				Version: ver,
			}
		case "<":
			candidate := strings.TrimSuffix(fields[6], ")")
			packs[name] = models.Package{
				Name:       name,
				Version:    ver,
				NewVersion: candidate,
			}
		case ">":
			o.log.Warn("The installed version of the %s is newer than the current version. *This situation can arise with an out of date index file, or when testing new ports.*", name)
			packs[name] = models.Package{
				Name:    name,
				Version: ver,
			}
		}
	}
	return packs
}

type vulnIDCveIDs2 struct {
	vulnID string
	cveIDs []string
}

type pkgAuditResult2 struct {
	pack          models.Package
	vulnIDCveIDs2 vulnIDCveIDs2
}

func (o *archlinux) splitIntoBlocks(stdout string) (blocks []string) {
	lines := strings.Split(stdout, "\n")
	block := []string{}
	for _, l := range lines {
		if len(strings.TrimSpace(l)) == 0 {
			if 0 < len(block) {
				blocks = append(blocks, strings.Join(block, "\n"))
				block = []string{}
			}
			continue
		}
		block = append(block, strings.TrimSpace(l))
	}
	if 0 < len(block) {
		blocks = append(blocks, strings.Join(block, "\n"))
	}
	return
}

func (o *archlinux) parseBlock(block string) (packName string, cveIDs []string, vulnID string) {
	lines := strings.Split(block, "\n")
	for _, l := range lines {
		if strings.HasSuffix(l, " is vulnerable:") {
			packVer := strings.Fields(l)[0]
			splitted := strings.Split(packVer, "-")
			packName = strings.Join(splitted[:len(splitted)-1], "-")
		} else if strings.HasPrefix(l, "CVE:") {
			cveIDs = append(cveIDs, strings.Fields(l)[1])
		} else if strings.HasPrefix(l, "WWW:") {
			splitted := strings.Split(l, "/")
			vulnID = strings.TrimSuffix(splitted[len(splitted)-1], ".html")
		}
	}
	return
}
