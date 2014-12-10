<?php

/**
 * Class IPsecTunnelStore
 * @property $o IPsecTunnel[]
 */
class IPsecTunnelStore extends ObjStore
{

    /**
     * @var null|string[]|DOMElement
     */
    public $xmlroot=null;

    /**
     * @var null|PANConf
     */
    public $owner=null;

    public function IPsecTunnelStore($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
    }

    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 ) continue;

            $ns = new IPsecTunnel('tmp',$this);
            $ns->load_from_domxml($node);
            //print $this->toString()." : new IPsec tunnel '".$ns->name()."' found\n";

            $this->o[] = $ns;
        }
    }

    /**
     * @param Array[] $xml
     */
    public function load_from_xml( &$xml)
    {
        $this->xmlroot = $xml;

        foreach( $xml['children'] as &$children )
        {
            $ns = new IPsecTunnel('tmp',$this);
            $ns->load_from_xml($children);
            //print $this->toString()." : new IPsec tunnel '".$ns->name()."' found\n";

            $this->o[] = $ns;
        }
    }

    /**
     * @return IPsecTunnel[]
     */
    public function tunnels()
    {
        return $this->o;
    }


} 