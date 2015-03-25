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

        $tmp = DH::findFirstElementOrCreate('interface', $this->xmlroot);
        $tmp = DH::findFirstElementOrCreate('ethernet', $tmp);
        $this->ethernetIfStore->load_from_domxml($tmp);

    }

    /**
     * @return EthernetInterface[]|IPsecTunnel
     */
    function getAllInterfaces()
    {
        $ifs = Array();

        foreach( $this->ethernetIfStore->getInterfaces() as $if )
            $ifs[] = $if;

        foreach( $this->ipsecTunnelStore->getAll() as $if )
            $ifs[] = $if;

        return $ifs;
    }

    /**
     * @param string $ip
     * @return EthernetInterface[]|IPsecTunnel[]
     */
    function findInterfacesNetworkMatchingIP( $ip )
    {
        $ifs = Array();

        foreach( $this->ethernetIfStore->getInterfaces() as $if )
        {
            if( $if->type() == 'layer3' )
            {
                $ipAddresses = $if->getLayer3IPv4Addresses();
                foreach( $ipAddresses as $ipAddress )
                {
                    if( cidr::netMatch($ip, $ipAddress) > 0)
                    {
                        $ifs[] = $if;
                        break;
                    }
                }
            }
        }


        return $ifs;
    }

}


trait InterfaceType
{
    public function isEthernetType() { return false; }
    public function isIPsecTunnelType() { return false; }
    public function isAggregateType()  { return false; }
}