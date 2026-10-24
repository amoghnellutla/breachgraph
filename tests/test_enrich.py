import httpx
import respx

from tests.conftest import make_finding, make_vuln
from triagegate.config import Enrich
from triagegate.enrich import EPSS_URL, KEV_URL, enrich

KEV_BODY = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "dateAdded": "2021-12-10",
            "knownRansomwareCampaignUse": "Known",
        }
    ]
}


@respx.mock
def test_enrich_sets_kev_and_epss() -> None:
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=KEV_BODY))
    epss = respx.get(EPSS_URL).mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.999"}]},
        )
    )
    log4j, other = make_vuln(), make_vuln(cve="CVE-2099-0001", pkg="x")
    warnings = enrich([log4j, other, make_finding()], Enrich())
    assert warnings == []
    assert log4j.enrichment.kev and log4j.enrichment.kev_ransomware
    assert log4j.enrichment.epss == 0.97
    assert not other.enrichment.kev and other.enrichment.epss is None
    assert "CVE-2021-44228" in epss.calls[0].request.url.params["cve"]


@respx.mock
def test_enrich_uses_cache() -> None:
    kev = respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=KEV_BODY))
    epss = respx.get(EPSS_URL).mock(return_value=httpx.Response(200, json={"data": []}))
    enrich([make_vuln()], Enrich())
    enrich([make_vuln()], Enrich())
    assert kev.call_count == 1
    assert epss.call_count == 1


@respx.mock
def test_enrich_degrades_gracefully_offline() -> None:
    respx.get(KEV_URL).mock(side_effect=httpx.ConnectError("no network"))
    respx.get(EPSS_URL).mock(return_value=httpx.Response(503))
    f = make_vuln()
    warnings = enrich([f], Enrich())
    assert len(warnings) == 2
    assert not f.enrichment.kev


def test_enrich_offline_flag_makes_no_requests() -> None:
    with respx.mock(assert_all_called=False) as router:
        route = router.get(KEV_URL)
        assert enrich([make_vuln()], Enrich(), offline=True) == []
        assert not route.called


@respx.mock
def test_epss_batches_large_requests() -> None:
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))
    epss = respx.get(EPSS_URL).mock(return_value=httpx.Response(200, json={"data": []}))
    vulns = [make_vuln(cve=f"CVE-2024-{i:05d}", pkg=f"p{i}") for i in range(250)]
    enrich(vulns, Enrich())
    assert epss.call_count == 3
