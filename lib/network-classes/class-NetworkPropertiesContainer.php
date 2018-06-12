<?php


class NetworkPropertiesContainer
{
    use PathableName;

    /** @var PANConf|PanoramaConf */
    public $owner;

    /** @var EthernetIfStore */
    public $ethernetIfStore;

    /** @var AggregateEthernetIfStore */
    public $aggregateEthernetIfStore;

    /** @var IPsecTunnelStore */
    public $ipsecTunnelStore;

    /** @var LoopbackIfStore */
    public $loopbackIfStore;

    /** @var TmpInterfaceStore */
    public $tmpInterfaceStore;

    /** @var VirtualRouterStore */
    public $virtualRouterStore;

    /** @var Ike2CryptoProfileStore */
    public $ikeCryptoProfileStore;

    /** @var IPSecCryptoProfileStore */
    public $ipsecCryptoProfileStore;

    /** @var DOMElement|null */
    public $xmlroot = null;


    /**
     * NetworkPropertiesContainer constructor.
     * @param PANConf|PanoramaConf $owner
     */
    function __construct($owner)
    {
        $this->owner = $owner;
        $this->ethernetIfStore = new EthernetIfStore('EthernetIfaces', $owner);
        $this->aggregateEthernetIfStore = new EthernetIfStore('AggregateEthernetIfaces', $owner);
        $this->loopbackIfStore = new LoopbackIfStore('LoopbackIfaces', $owner);
        $this->ipsecTunnelStore = new IPsecTunnelStore('IPsecTunnels', $owner);
        $this->tmpInterfaceStore = new TmpInterfaceStore('TmpIfaces', $owner);
        $this->virtualRouterStore = new VirtualRouterStore('', $owner);
        $this->ikeCryptoProfileStore = new Ike2CryptoProfileStore('IkeCryptoProfiles', $owner);
        $this->ipsecCryptoProfileStore = new IPSecCryptoProfileStore('IPSecCryptoProfiles', $owner);
        $this->ikeGatewayStore = new IKEGatewayStore('IkeGateways', $owner);
        $this->vlanIfStore = new VlanIfStore('VlanIfaces', $owner);
        $this->tunnelIfStore = new TunnelIfStore('TunnelIfaces', $owner);
    }

    function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;
        $tmp = DH::findFirstElementOrCreate('ike', $this->xmlroot);
        if( $tmp !== false )
        {
            $tmp_crypto = DH::findFirstElementOrCreate('crypto-profiles', $tmp);
            if( $tmp_crypto !== FALSE )
            {
                $tmp_ike = DH::findFirstElement('ike-crypto-profiles', $tmp_crypto);
                if( $tmp_ike !== FALSE )
                {
                    $this->ikeCryptoProfileStore->load_from_domxml($tmp_ike);
                }

                $tmp_ipsec = DH::findFirstElement('ipsec-crypto-profiles', $tmp_crypto);
                if( $tmp_ipsec !== FALSE )
                {
                    $this->ipsecCryptoProfileStore->load_from_domxml($tmp_ipsec);
                }
            }

            $tmp2 = DH::findFirstElementOrCreate('gateway', $tmp);
            if( $tmp2 !== FALSE )
            {
                $this->ikeGatewayStore->load_from_domxml($tmp2);
            }
        }
        $tmp = DH::findFirstElementOrCreate('tunnel', $this->xmlroot);
        if( $tmp !== false )
        {
            $tmp = DH::findFirstElement('ipsec', $tmp);
            if( $tmp !== FALSE )
                $this->ipsecTunnelStore->load_from_domxml($tmp);
        }

        $tmp = DH::findFirstElementOrCreate('interface', $this->xmlroot);
        $tmp = DH::findFirstElement('ethernet', $tmp);
        if( $tmp !== false )
            $this->ethernetIfStore->load_from_domxml($tmp);

        $tmp = DH::findFirstElementOrCreate('interface', $this->xmlroot);
        $tmp = DH::findFirstElement('aggregate-ethernet', $tmp);
        if( $tmp !== false )
            $this->aggregateEthernetIfStore->load_from_domxml($tmp);

        $tmp = DH::findFirstElementOrCreate('interface', $this->xmlroot);
        $tmp = DH::findFirstElement('loopback', $tmp);
        if( $tmp !== false )
        {
            $tmp = DH::findFirstElement('units', $tmp);
            if( $tmp !== false )
                $this->loopbackIfStore->load_from_domxml($tmp);
        }

        $tmp = DH::findFirstElementOrCreate('interface', $this->xmlroot);
        $tmp = DH::findFirstElement('vlan', $tmp);
        if( $tmp !== false )
        {
            $tmp = DH::findFirstElement('units', $tmp);
            if( $tmp !== false )
                $this->vlanIfStore->load_from_domxml($tmp);
        }

        $tmp = DH::findFirstElementOrCreate('interface', $this->xmlroot);
        $tmp = DH::findFirstElement('tunnel', $tmp);
        if( $tmp !== false )
        {
            $tmp = DH::findFirstElement('units', $tmp);
            if( $tmp !== false )
                $this->tunnelIfStore->load_from_domxml($tmp);
        }


        $tmp = DH::findFirstElementOrCreate('virtual-router', $this->xmlroot);
        $this->virtualRouterStore->load_from_domxml($tmp);
    }

    /**
     * @return EthernetInterface[]|IPsecTunnel[]|LoopbackInterface[]|AggregateEthernetInterface[]|TmpInterface[]|VlanInterface[]
     */
    function getAllInterfaces()
    {
        $ifs = Array();

        foreach( $this->ethernetIfStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->aggregateEthernetIfStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->loopbackIfStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->ipsecTunnelStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->vlanIfStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->tunnelIfStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->tmpInterfaceStore->getInterfaces() as $if )
            if( $if->name() == $if )
                return $if;

        return $ifs;
    }

    /**
     * @param string $interfaceName
     * @return EthernetInterface|IPsecTunnel|TmpInterface|VlanInterface|TunnelInterface|null
     */
    function findInterface( $interfaceName )
    {
        foreach( $this->ethernetIfStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        foreach( $this->aggregateEthernetIfStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        foreach( $this->loopbackIfStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        foreach( $this->ipsecTunnelStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        foreach( $this->vlanIfStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        foreach( $this->tunnelIfStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        foreach( $this->tmpInterfaceStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        return null;
    }

    /**
     * Convenient alias to findInterface
     * @param string $interfaceName
     * @return EthernetInterface|IPsecTunnel|TmpInterface|VlanInterface|null
     */
    public function find($interfaceName)
    {
        return $this->findInterface($interfaceName);
    }


    /**
     * @param string $interfaceName
     * @return null|VirtualSystem
     */
    function findVsysInterfaceOwner( $interfaceName )
    {
        foreach( $this->owner->virtualSystems as $vsys )
        {
            if( $vsys->importedInterfaces->hasInterfaceNamed($interfaceName) )
                return $vsys;
        }

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
     * @param string $ip
     * @return EthernetInterface[]|IPsecTunnel[]|LoopbackInterface[]|AggregateEthernetInterface[]
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

        foreach( $this->loopbackIfStore->getInterfaces() as $if )
        {
            $ipAddresses = $if->getIPv4Addresses();
            foreach( $ipAddresses as $ipAddress )
            {
                if( cidr::netMatch($ip, $ipAddress) > 0)
                {
                    $ifs[] = $if;
                    break;
                }
            }
        }


        foreach( $this->vlanIfStore->getInterfaces() as $if )
        {
            $ipAddresses = $if->getIPv4Addresses();
            foreach( $ipAddresses as $ipAddress )
            {
                if( cidr::netMatch($ip, $ipAddress) > 0)
                {
                    $ifs[] = $if;
                    break;
                }
            }
        }

        foreach( $this->tunnelIfStore->getInterfaces() as $if )
        {
            $ipAddresses = $if->getIPv4Addresses();
            foreach( $ipAddresses as $ipAddress )
            {
                if( cidr::netMatch($ip, $ipAddress) > 0)
                {
                    $ifs[] = $if;
                    break;
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
    public function isLoopbackType()  { return false; }

    public $importedByVSYS = null;
}