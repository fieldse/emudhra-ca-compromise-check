##! emudhra-ca.zeek - notices for the eMudhra G3 intermediate CA key compromise (October 2026).
##! Raises a notice when a TLS chain carries a compromised intermediate, a certificate issued by one,
##! or a G3 root. Certificates are visible in TLS 1.2 and older only.
##! Source: https://github.com/fieldse/emudhra-ca-check  Revised 2026-10-31.

module EMudhra;

export {
	redef enum Notice::Type += {
		## A certificate in the chain is one of the 16 compromised intermediates.
		Compromised_Intermediate,
		## A certificate names one of the eight compromised intermediates as its issuer.
		Issued_By_Compromised_Intermediate,
		## A certificate in the chain is emSign ECC Root CA - G3 or a G3 issuing root.
		G3_Root_In_Chain,
	};

	## SHA-256 of each compromised intermediate, eMudhra-issued and Sectigo cross-signed.
	const compromised: table[string] of string = {
		["42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493"] = "EM DV TLS CA - G3B",
		["45a883f349aedfd5f3a649b5498ffb121712ba8b448f3f2a91dbc5a766fcddbe"] = "EM DV TLS CA - G3B (Sectigo cross-sign)",
		["98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b"] = "EM OV TLS CA - G3B",
		["5f1ded4dd590af74631290cf073b122a2aac6a1fa479778a0bd43579bd832699"] = "EM OV TLS CA - G3B (Sectigo cross-sign)",
		["e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838"] = "EM EV TLS CA - G3B",
		["579480aea166290bd3c643589e795fc0d0e54e86505d180f1dff99efd3199512"] = "EM EV TLS CA - G3B (Sectigo cross-sign)",
		["0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19"] = "EM DV TLS CA - G3C",
		["62b7f9868263f72f6911fc78ceaf72c1979158b7368bf648683bb2aa39b02e72"] = "EM DV TLS CA - G3C (Sectigo cross-sign)",
		["cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f"] = "EM OV TLS CA - G3C",
		["7485b51c0ed192878fa1d2f948fb529ae1842cc5086c4b67f7be5b2039de9489"] = "EM OV TLS CA - G3C (Sectigo cross-sign)",
		["432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3"] = "EM EV TLS CA - G3C",
		["fd9d5c2dbbd4995ab69b8d50c439d9527b00529199c2fd01b2174eb58f07021f"] = "EM EV TLS CA - G3C (Sectigo cross-sign)",
		["9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4"] = "EM OV CS CA - G3B",
		["a496e23ac0cab8155fc9b117b97eae368efcbb9041aec8804d5a308d2d01c2d8"] = "EM OV CS CA - G3B (Sectigo cross-sign)",
		["4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1"] = "EM OV CS CA - G3C",
		["84112972b8e59d14560ae7e7119654474aad119990cf3722bfc1e3b91615e1fd"] = "EM OV CS CA - G3C (Sectigo cross-sign)"
	} &redef;

	## SHA-256 of the removed root and the two roots that issued the intermediates.
	const g3_roots: table[string] of string = {
		["86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"] = "emSign ECC Root CA - G3",
		["7dd78d5f4f13459a83dff9abbba62edbaf6f2d102bf257fd712f4d9f2746ed8d"] = "emSign Root TLS CA - G3",
		["f2edaaff3d9b701fb4d14c9f285f8c0bad90fc3bcc1fa07d47f4718edaba34a5"] = "emSign Root CS CA - G3"
	} &redef;

	## Issuer names of the eight compromised intermediates.
	const compromised_issuer = /CN=EM (DV|OV|EV) (TLS|CS) CA - G3[BC](,|$)/ &redef;
}

# Raise the notices that apply to one certificate.
function check(f: fa_file, fp: string, cert: X509::Certificate)
	{
	local who = fmt("subject=%s issuer=%s sha256=%s", cert$subject, cert$issuer, fp);
	if ( fp in compromised )
		NOTICE([$note=Compromised_Intermediate, $f=f, $identifier=fp,
		        $msg=fmt("Compromised eMudhra intermediate in chain: %s", compromised[fp]), $sub=who]);
	else if ( fp in g3_roots )
		NOTICE([$note=G3_Root_In_Chain, $f=f, $identifier=fp,
		        $msg=fmt("eMudhra G3 root in chain: %s", g3_roots[fp]), $sub=who]);
	else if ( compromised_issuer in cert$issuer )
		NOTICE([$note=Issued_By_Compromised_Intermediate, $f=f, $identifier=fp,
		        $msg=fmt("Certificate issued by a compromised eMudhra intermediate: %s", cert$issuer), $sub=who]);
	}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) &priority=3
	{
	check(f, sha256_hash(x509_get_certificate_string(cert_ref)), cert);
	}

# Zeek skips x509_certificate for certificates it has cached; this hook still sees them.
hook X509::x509_certificate_cache_replay(f: fa_file, e: X509::Info, sha256: string)
	{
	check(f, sha256, e$certificate);
	}
