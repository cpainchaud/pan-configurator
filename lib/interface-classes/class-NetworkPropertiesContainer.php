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

    public $ipsecTunnelStore;


    function NetworkPropertiesContainer(PANConf $owner)
    {
        $this->owner = $owner;
        $this->ethernetIfStore = new EthernetIfStore($owner);
        $this->ipsecTunnelStore = new IPsecTunnelStore('IPsec Tunnels', $owner);
    }

}