GEN_BASE = generated/qcsapi_rpc

define DUAL_LICENSE
/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2017 Quantenna Communications, Inc.          **
**                                                                           **
**  File        :                                                            **
**  Description :                                                            **
**                                                                           **
*******************************************************************************
**                                                                           **
**  Redistribution and use in source and binary forms, with or without       **
**  modification, are permitted provided that the following conditions       **
**  are met:                                                                 **
**  1. Redistributions of source code must retain the above copyright        **
**     notice, this list of conditions and the following disclaimer.         **
**  2. Redistributions in binary form must reproduce the above copyright     **
**     notice, this list of conditions and the following disclaimer in the   **
**     documentation and/or other materials provided with the distribution.  **
**  3. The name of the author may not be used to endorse or promote products **
**     derived from this software without specific prior written permission. **
**                                                                           **
**  Alternatively, this software may be distributed under the terms of the   **
**  GNU General Public License (\"GPL\") version 2, or (at your option) any  **
**  later version as published by the Free Software Foundation.              **
**                                                                           **
**  In the case this software is distributed under the GPL license,          **
**  you should have received a copy of the GNU General Public License        **
**  along with this software; if not, write to the Free Software             **
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  **
**                                                                           **
**  THIS SOFTWARE IS PROVIDED BY THE AUTHOR \"AS IS\" AND ANY EXPRESS OR     **
**  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES**
**  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  **
**  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,         **
**  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT **
**  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,**
**  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY    **
**  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT      **
**  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF **
**  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.        **
**                                                                           **
*******************************************************************************
EH0*/
endef
export DUAL_LICENSE

.PHONY: generate clean

generate: $(GEN_BASE)_svc.c $(GEN_BASE)_clnt.c $(GEN_BASE).h

%_svc.c: %.x %.h
	cd ${@D} && rpcgen -M -m ${<F} > ${@F}

%_clnt.c %.h: %.x
	cd ${@D} && rpcgen -M ${<F}
	@echo "$$DUAL_LICENSE" > $(GEN_BASE).h.tmp
	cat $(GEN_BASE).h >> $(GEN_BASE).h.tmp
	mv $(GEN_BASE).h.tmp $(GEN_BASE).h
	@echo "$$DUAL_LICENSE" > $(GEN_BASE)_xdr.c.tmp
	cat $(GEN_BASE)_xdr.c >> $(GEN_BASE)_xdr.c.tmp
	mv $(GEN_BASE)_xdr.c.tmp $(GEN_BASE)_xdr.c

$(GEN_BASE).x: qcsapi_rpc_gen.pl ../qcsapi.conf ../qcsapi.h
	@mkdir -p ${@D}
	perl qcsapi_rpc_gen.pl ../qcsapi.h ../qcsapi.conf

clean:
	rm -rf generated/

