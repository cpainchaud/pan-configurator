<?php


class NetworkPropertiesContainer
{
    /**
     * @var PANConf
     */
    public $owner;


    /**
     * @var EthernetIfStore
     */
    public $ethernetIfStore;

    /**
     * @var IPsecTunnelStore
     */
    public $ipsecTunnelStore;

    /**
     * @var DOMElement|null
     */
    public $xmlroot = null;


    function NetworkPropertiesContainer(PANConf $owner)
    {
        $this->owner = $owner;
        $this->ethernetIfStore = new EthernetIfStore('EthernetIfaces', $owner);
        $this->ipsecTunnelStore = new IPsecTunnelStore('IPsecTunnels', $owner);
    }

    function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $tmp = DH::findFirstElementOrCreate('tunnel', $this->xmlroot);
        $tmp = DH::findFirstElementOrCreate('ipsec', $tmp);
        $this->ipsecTunnelStore->load_from_domxml($tmp);

        $tmp = DH::findFirstElementOrCreate('ethernet', $this->xmlroot);
        $this->ethernetIfStore->load_from_domxml($tmp);

    }

}