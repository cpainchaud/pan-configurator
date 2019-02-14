<?php
/*
 * Copyright (c) 2014-2017 Christophe Painchaud <shellescape _AT_ gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

class EthernetInterface
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferencableObject;

    /** @var null|DOMElement */
    private $typeRoot = null;

    /** @var EthernetIfStore */
    public $owner;


    /** @var string */
    public $type = 'tmp';

    /** @var string */
    public $description;

    /** @var bool */
    protected $isSubInterface = false;

    /** @var EthernetInterface[] */
    protected $subInterfaces = Array();

    /** @var null|EthernetInterface */
    protected $parentInterface = null;

    /** @var int */
    protected $tag;

    /** @var int */
    protected $ae = null;

    protected $l3ipv4Addresses;

    static public $supportedTypes = Array( 'layer3', 'layer2', 'virtual-wire', 'tap', 'ha', 'aggregate-group', 'log-card', 'decrypt-mirror', 'empty' );

    /**
     * @param string $name
     * @param EthernetIfStore $owner
     */
    function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
    }

    /**
     * @param DOMElement $xml
     */
    function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        //print "Int name found: {$this->name}\n";
        if( $this->name === FALSE )
            derr("address name not found\n");

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            $nodeName = $node->nodeName;

            if( array_search($nodeName, self::$supportedTypes) !== false )
            {
                $this->type = $nodeName;
                $this->typeRoot = $node;
            }
            elseif( $nodeName == 'comment' )
            {
                $this->description = $node->textContent;
                //print "Desc found: {$this->description}\n";
            }
        }

        if( $this->type == 'tmp' )
        {
            $this->type = 'empty';
            return;
        }

        if( $this->type == 'layer3' )
        {
            $this->l3ipv4Addresses = Array();
            $ipNode = DH::findFirstElement('ip', $this->typeRoot);
            if( $ipNode !== false )
            {
                foreach( $ipNode->childNodes as $l3ipNode )
                {
                    if( $l3ipNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $this->l3ipv4Addresses[] = $l3ipNode->getAttribute('name');
                }
            }
        }

        if( $this->type == 'aggregate-group' )
        {
            $this->ae = $this->typeRoot->textContent;
            //print "AE: ".$this->ae."\n";
        }


        // looking for sub interfaces and stuff like that   :)
        foreach( $this->typeRoot->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            // sub interfaces here !
            if( $node->nodeName == 'units' )
            {
                foreach( $node->childNodes as $unitsNode )
                {
                    if( $unitsNode->nodeType != 1 )
                        continue;

                    $newInterface = new EthernetInterface('tmp', $this->owner );
                    $newInterface->isSubInterface = true;
                    $newInterface->parentInterface = $this;
                    $newInterface->type = &$this->type;
                    $newInterface->load_sub_from_domxml($unitsNode);
                    $this->subInterfaces[] = $newInterface;
                }
            }
        }
    }

    /**
     * @param DOMElement $xml
     */
    public function load_sub_from_domxml($xml)
    {
        $this->xmlroot = $xml;
        $this->name = DH::findAttribute('name', $xml);
        //print "subInt name found: {$this->name}\n";
        if( $this->name === FALSE )
            derr("address name not found\n");

        foreach( $xml->childNodes as $node )
        {
            if ($node->nodeType != 1)
                continue;

            $nodeName = $node->nodeName;

            if( $nodeName == 'comment' )
            {
                $this->description = $node->textContent;
                //print "Desc found: {$this->description}\n";
            }
            elseif( $nodeName == 'tag' )
            {
                $this->tag = $node->textContent;
            }
            elseif( $nodeName == 'aggregate-group' )
            {
                $this->ae = $node->textContent;
            }
        }

        if( $this->type == 'layer3' )
        {
            $this->l3ipv4Addresses = Array();
            $ipNode = DH::findFirstElement('ip', $xml);
            if( $ipNode !== false )
            {
                foreach( $ipNode->childNodes as $l3ipNode )
                {
                    if( $l3ipNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $this->l3ipv4Addresses[] = $l3ipNode->getAttribute('name');
                }
            }
        }
    }

    /**
     * @return bool
     */
    public function isSubInterface()
    {
        return $this->isSubInterface;
    }

    /**
     * @return string
     */
    public function type()
    {
        return $this->type;
    }

    /**
     * @return int
     */
    public function tag()
    {
        return $this->tag;
    }

    /**
     * @return int
     */
    public function ae()
    {
        return $this->ae;
    }

    /**
     * @return int
     */
    public function subIfNumber()
    {
        if( !$this->isSubInterface )
            derr('can be called in sub interfaces only');

        $ar = explode('.', $this->name);

        if( count($ar) != 2 )
            derr('unsupported');

        return $ar[1];
    }

    public function getLayer3IPv4Addresses()
    {
        if( $this->type != 'layer3' )
            derr('cannot be requested from a non Layer3 Interface');

        if( $this->l3ipv4Addresses === null )
            return Array();

        return $this->l3ipv4Addresses;
    }

    public function countSubInterfaces()
    {
        return count($this->subInterfaces);
    }

    /**
     * @return EthernetInterface[]
     */
    public function subInterfaces()
    {
        return $this->subInterfaces;
    }

    function isEthernetType() { return true; }
    function isAggregateTypeType() { return false; }

    /**
     * return true if change was successful false if not (duplicate rulename?)
     * @return bool
     * @param string $name new name for the rule
     */
    public function setName($name)
    {
        if( $this->name == $name )
            return true;

        $this->name = $name;

        $this->xmlroot->setAttribute('name', $name);

        return true;

    }

    /**
     * return true if change was successful false if not (duplicate rulename?)
     * @return bool
     * @param string $name new name for the rule
     */
    public function setTag($tag)
    {
        if( $this->type != 'layer3' && $this->type != 'layer2' && $this->type != 'virtual-wire')
            derr('cannot be requested from a '.$this->type().' Interface');

        if( $this->tag == $tag )
            return true;

        $this->tag = $tag;

        $tagNode = DH::findFirstElement( 'tag', $this->xmlroot);
        DH::setDomNodeText( $tagNode, $tag);

        return true;
    }

    /**
     * return true if change was successful false if not (duplicate rulename?)
     * @return bool
     * @param string $name new name for the rule
     */
    public function setAE($ae)
    {
        if( $this->type != 'aggregate-group')
            derr('cannot be requested from a '.$this->type().' Interface');

        if( $this->ae == $ae )
            return true;

        $this->ae = $ae;

        $aeNode = DH::findFirstElement( 'aggregate-group', $this->xmlroot);
        DH::setDomNodeText( $aeNode, $ae);

        return true;
    }

    /**
     * return true if change was successful false if not (duplicate ipaddress?)
     * @return bool
     * @param string $ip
     */
    public function addIPv4Address($ip)
    {
        if( $this->type != 'layer3' )
            derr('cannot be requested from a non Layer3 Interface');

        if( strpos($ip, "/") === FALSE )
        {
            $tmp_vsys = $this->owner->owner->network->findVsysInterfaceOwner($this->name());
            $object = $tmp_vsys->addressStore->find($ip);

            if( is_object($object) )
                $object->addReference($this);
            else
                derr("objectname: " . $ip . " not found. Can not be added to interface.\n", $this);
        }

        foreach( $this->getLayer3IPv4Addresses() as $IPv4Address )
        {
            if( $IPv4Address == $ip )
                return true;
        }

        $this->l3ipv4Addresses[] = $ip;

        if( $this->isSubInterface() )
            $tmp_xmlroot = $this->parentInterface->xmlroot;
        else
            $tmp_xmlroot = $this->xmlroot;

        $layer3Node = DH::findFirstElementOrCreate('layer3', $tmp_xmlroot);

        if( $this->isSubInterface() )
        {
            $tmp_units = DH::findFirstElementOrCreate('units', $layer3Node);
            $tmp_entry = DH::findFirstElementByNameAttrOrDie( 'entry', $this->name() , $tmp_units );
            $ipNode = DH::findFirstElementOrCreate('ip', $tmp_entry);
        }
        else
            $ipNode = DH::findFirstElementOrCreate('ip', $layer3Node);


        $tmp_ipaddress = DH::createElement($ipNode, 'entry', "" );
        $tmp_ipaddress->setAttribute( 'name', $ip );

        $ipNode->appendChild( $tmp_ipaddress );

        return true;
    }

    /**
     * Add a ip to this interface, it must be passed as an object or string
     * @param Address $ip Object to be added, or String
     * @return bool
     */
    public function API_addIPv4Address($ip)
    {
        $ret = $this->addIPv4Address($ip);

        if( $ret )
        {
            $con = findConnector($this);
            $xpath = $this->getXPath();

            if( $this->isSubInterface() )
            {
                $xpath = $this->parentInterface->getXPath();
                $xpath .= "/layer3/units/entry[@name='".$this->name."']/ip";
            }
            else
                $xpath .= '/layer3/ip';

            $con->sendSetRequest($xpath, "<entry name='{$ip}'/>");
        }

        return $ret;
    }

    /**
     * return true if change was successful false if not (duplicate ipaddress?)
     * @return bool
     * @param string $ip
     */
    public function removeIPv4Address($ip)
    {
        if( $this->type != 'layer3' )
            derr('cannot be requested from a non Layer3 Interface');

        $tmp_IPv4 = array();
        foreach( $this->getLayer3IPv4Addresses() as $key => $IPv4Address )
        {
            $tmp_IPv4[ $IPv4Address ] = $IPv4Address;
            if( $IPv4Address == $ip )
                unset( $this->l3ipv4Addresses[$key] );
        }


        if( !array_key_exists ( $ip , $tmp_IPv4 ) )
        {
            print "\n ** skipped ** IP Address: ".$ip." is not set on interface: ".$this->name()."\n";
            return false;
        }

        if( strpos($ip, "/") === FALSE )
        {
            $tmp_vsys = $this->owner->owner->network->findVsysInterfaceOwner($this->name());
            $object = $tmp_vsys->addressStore->find($ip);

            if( is_object($object) )
                $object->removeReference($this);
            else
                mwarning("objectname: " . $ip . " not found. Can not be removed from interface.\n", $this);
        }

        if( $this->isSubInterface() )
            $tmp_xmlroot = $this->parentInterface->xmlroot;
        else
            $tmp_xmlroot = $this->xmlroot;

        $layer3Node = DH::findFirstElementOrCreate('layer3', $tmp_xmlroot);

        if( $this->isSubInterface() )
        {
            $tmp_units = DH::findFirstElementOrCreate('units', $layer3Node);
            $tmp_entry = DH::findFirstElementByNameAttrOrDie( 'entry', $this->name() , $tmp_units );
            $ipNode = DH::findFirstElementOrCreate('ip', $tmp_entry);
        }
        else
            $ipNode = DH::findFirstElementOrCreate('ip', $layer3Node);


        $tmp_ipaddress = DH::findFirstElementByNameAttrOrDie( 'entry', $ip , $ipNode );
        $ipNode->removeChild( $tmp_ipaddress);

        return true;
    }

    /**
     * remove a ip address to this interface, it must be passed as an object or string
     * @param Address $ip Object to be added, or String
     * @return bool
     */
    public function API_removeIPv4Address($ip)
    {
        $ret = $this->removeIPv4Address($ip);

        if( $ret )
        {
            $con = findConnector($this);
            $xpath = $this->getXPath();

            if( $this->isSubInterface() )
            {
                $xpath = $this->parentInterface->getXPath();
                $xpath .= "/layer3/units/entry[@name='".$this->name."']/ip";
            }
            else
                $xpath .= '/layer3/ip';

            $con->sendDeleteRequest( $xpath."/entry[@name='{$ip}']" );
        }

        return $ret;
    }

    /**
     * return true if change was successful false if not (duplicate ipaddress?)
     * @return EthernetInterface
     * @param string $ip
     */
    public function addSubInterface( $tag )
    {
        if( $this->type != 'layer3' && $this->type != 'layer2' && $this->type != 'virtual-wire')
            derr('cannot be requested from a '.$this->type().' Interface');


        $tmp_xmlroot = $this->xmlroot;
        $typeNode = DH::findFirstElement( $this->type, $tmp_xmlroot);
        $unit = DH::findFirstElementOrCreate( 'units', $typeNode);


        if( $this->type == 'layer3' )
            $xmlElement = DH::importXmlStringOrDie($this->owner->owner->xmlroot->ownerDocument, EthernetInterface::$templatexmlsubl3);
        else
            $xmlElement = DH::importXmlStringOrDie($this->owner->owner->xmlroot->ownerDocument, EthernetInterface::$templatexmlsub);

        $newInterface = new EthernetInterface('tmp', $this->owner );
        $newInterface->isSubInterface = true;
        $newInterface->parentInterface = $this;
        $newInterface->type = &$this->type;
        $newInterface->load_sub_from_domxml($xmlElement);
        $this->subInterfaces[] = $newInterface;


        $newInterface->setName( $this->name.".".$tag );
        $newInterface->setTag( $tag );

        $unit->appendChild( $xmlElement );

        return $newInterface;
    }


    /**
     * Add a ip to this interface, it must be passed as an object or string
     * @param Address $ip Object to be added, or String
     * @return EthernetInterface
     */
    public function API_addSubInterface($tag)
    {
        $ret = $this->addSubInterface($tag);

        if( is_object( $ret ) )
        {
            $con = findConnector($this);

            $xpath = $this->getXPath();
            $xpath .= "/".$this->type()."/units";

            $con->sendSetRequest($xpath, "<entry name='{$this->name}.{$tag}'><tag>{$tag}</tag></entry>");
        }

        return $ret;
    }



    //Todo: (20180722)
    //---(also needed for vlan / loopback / tunnel interface)
    //- add Virtual Router
    //- add Security Zone
    //- add Virtual System
    //- add Comment (low prio)
    //- add Management Profile (low prio)




    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getEthernetIfStoreXPath()."/entry[@name='".$this->name."']";

        return $str;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**">
  <layer3>
    <ipv6>
      <neighbor-discovery>
        <router-advertisement>
          <enable>no</enable>
        </router-advertisement>
      </neighbor-discovery>
    </ipv6>
    <ndp-proxy>
      <enabled>no</enabled>
    </ndp-proxy>
    <lldp>
      <enable>no</enable>
    </lldp>
    <ip></ip>
  </layer3>
</entry>';

    static public $templatexmll2 = '<entry name="**temporarynamechangeme**">
    <layer2>
        <lldp>
        <enable>no</enable>
        </lldp>
    </layer2>
</entry>';

    static public $templatexmlvw = '<entry name="**temporarynamechangeme**">
<virtual-wire>
<lldp>
  <enable>no</enable>
</lldp>
</virtual-wire>
</entry>';

    static public $templatexmlae = '<entry name="**temporarynamechangeme**">
<aggregate-group>ae1</aggregate-group>
</entry>';


    static public $templatexmlsubl3 = '<entry name="**temporarynamechangeme**">
    <ipv6>
      <neighbor-discovery>
        <router-advertisement>
          <enable>no</enable>
        </router-advertisement>
      </neighbor-discovery>
    </ipv6>
    <ndp-proxy>
      <enabled>no</enabled>
    </ndp-proxy>
    <adjust-tcp-mss>
      <enable>no</enable>
    </adjust-tcp-mss>
    <tag></tag>
    <ip></ip>
</entry>';

    static public $templatexmlsub = '<entry name="**temporarynamechangeme**">
    <tag></tag>
</entry>';

}