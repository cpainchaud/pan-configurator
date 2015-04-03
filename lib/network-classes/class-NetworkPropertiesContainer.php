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
     * @var AggregateEthernetIfStore
     */
    public $aggregateEthernetIfStore;

    /**
     * @var IPsecTunnelStore
     */
    public $ipsecTunnelStore;

    /**
     * @var TmpInterfaceStore
     */
    public $tmpInterfaceStore;

    /**
     * @var VirtualRouterStore
     */
    public $virtualRouterStore;

    /**
     * @var DOMElement|null
     */
    public $xmlroot = null;


    function NetworkPropertiesContainer(PANConf $owner)
    {
        $this->owner = $owner;
        $this->ethernetIfStore = new EthernetIfStore('EthernetIfaces', $owner);
        $this->aggregateEthernetIfStore = new EthernetIfStore('AggregateEthernetIfaces', $owner);
        $this->ipsecTunnelStore = new IPsecTunnelStore('IPsecTunnels', $owner);
        $this->tmpInterfaceStore = new TmpInterfaceStore('TmpIfaces', $owner);
        $this->virtualRouterStore = new VirtualRouterStore('', $owner);
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

        $tmp = DH::findFirstElementOrCreate('interface', $this->xmlroot);
        $tmp = DH::findFirstElementOrCreate('aggregate-ethernet', $tmp);
        $this->aggregateEthernetIfStore->load_from_domxml($tmp);

        $tmp = DH::findFirstElementOrCreate('virtual-router', $this->xmlroot);
        $this->aggregateEthernetIfStore->load_from_domxml($tmp);

    }

    /**
     * @return EthernetInterface[]|IPsecTunnel[]
     */
    function getAllInterfaces()
    {
        $ifs = Array();

        foreach( $this->ethernetIfStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->aggregateEthernetIfStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->ipsecTunnelStore->getAll() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->tmpInterfaceStore->getAll() as $if )
            if( $if->name() == $if )
                return $if;

        return $ifs;
    }

    /**
     * @param string $interfaceName
     * @return EthernetInterface|IPsecTunnel|TmpInterface|null
     */
    function findInterface( $interfaceName )
    {
        foreach( $this->ethernetIfStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        foreach( $this->aggregateEthernetIfStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        foreach( $this->ipsecTunnelStore->getAll() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        foreach( $this->tmpInterfaceStore->getAll() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        return null;
    }

    /**
     * @param string $interfaceName
     * @return EthernetInterface|IPsecTunnel|TmpInterface
     */
    function findInterfaceOrCreateTmp( $interfaceName )
    {
        $resolved = $this->findInterface($interfaceName);

        if( $resolved !== null )
            return $resolved;

        return $this->tmpInterfaceStore->createTmp( $interfaceName );
    }

    /**
     * @param VirtualSystem $vsys
     * @return EthernetInterface|IPsecTunnel|null
     */
    function findInterfaceAttachedToVSYS( VirtualSystem $vsys )
    {
        $ifs = Array();

        foreach( $this->ethernetIfStore->getInterfaces() as $if )
            if( $if->importedByVSYS === $vsys )
                $ifs[$if->name()] = $if;

        foreach( $this->aggregateEthernetIfStore->getInterfaces() as $if )
            if( $if->importedByVSYS === $vsys )
                $ifs[$if->name()] = $if;

        foreach( $this->ipsecTunnelStore->getAll() as $if )
            if( $if->importedByVSYS === $vsys )
                $ifs[$if->name()] = $if;

        foreach( $this->tmpInterfaceStore->getAll() as $if )
            if( $if->importedByVSYS === $vsys )
                $ifs[$if->name()] = $if;

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

        foreach( $this->aggregateEthernetIfStore->getInterfaces() as $if )
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
    public function isTmpType()  { return false; }

    public $importedByVSYS = null;
}