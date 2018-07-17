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

/**
 * Class EthernetIfStore
 * @property EthernetInterface[] $o
 */
class EthernetIfStore extends ObjStore
{

    /** @var PANConf */
    public $owner;

    protected $fastMemToIndex=null;
    protected $fastNameToIndex=null;

    public static $childn = 'EthernetInterface';

    /**
     * @param PANConf $owner
     */
    function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
        $this->classn = &self::$childn;
    }


    function countSubInterfaces()
    {
        $count = 0;

        foreach($this->o as $interface)
        {
            $count += $interface->countSubInterfaces();
        }

        return $count;
    }


    /**
     * @return EthernetInterface[]
     */
    function getInterfaces()
    {
        return $this->o;
    }

    public function load_from_domxml(DOMElement $xml)
    {
        parent::load_from_domxml($xml);
        foreach( $this->o as $o )
        {
            foreach( $o->subInterfaces() as $sub )
            {
                $this->add($sub);
            }
        }
    }

    /**
     * Creates a new EthernetInterface in this store. It will be placed at the end of the list.
     * @param string $name name of the new EthernetInterface
     * @return EthernetInterface
     */
    public function newEthernetIf($name)
    {
        $ethernetIf = new EthernetInterface( $name, $this);
        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, EthernetInterface::$templatexml);

        $ethernetIf->load_from_domxml($xmlElement);

        $ethernetIf->owner = null;
        $ethernetIf->setName($name);

        $this->addEthernetIf( $ethernetIf );

        return $ethernetIf;
    }


    /**
     * @param EthernetInterface $ethernetIf
     * @return bool
     */
    public function addEthernetIf( $ethernetIf )
    {
        if( !is_object($ethernetIf) )
            derr('this function only accepts EthernetInterface class objects');

        if( $ethernetIf->owner !== null )
            derr('Trying to add a EthernetInterface that has a owner already !');


        $ser = spl_object_hash($ethernetIf);

        if (!isset($this->fastMemToIndex[$ser]))
        {
            $ethernetIf->owner = $this;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $this->xmlroot->appendChild($ethernetIf->xmlroot);

            return true;
        } else
            derr('You cannot add a EthernetInterface that is already here :)');

        return false;
    }

    /**
     * @param EthernetInterface $s
     * @return bool
     */
    public function API_addEthernetIf( $s )
    {
        $ret = $this->addEthernetIf($s);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $xpath = $s->getXPath();
            #print 'XPATH: '.$xpath->textContent."\n";
            $con->sendSetRequest($xpath, DH::domlist_to_xml($s->xmlroot->childNodes, -1, false) );
        }

        return $ret;
    }

    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            //TODO: 20180331 why I need to create full path? why it is not set before???
            $xml = DH::findFirstElementOrCreate('devices', $this->owner->xmlroot);
            $xml = DH::findFirstElementOrCreate('entry', $xml);
            $xml = DH::findFirstElementOrCreate('network', $xml);
            $xml = DH::findFirstElementOrCreate('interface', $xml);
            $xml = DH::findFirstElementOrCreate('ethernet', $xml);

            $this->xmlroot = DH::findFirstElementOrCreate('units', $xml);
        }
    }

    public function &getXPath()
    {
        $str = '';

        if( $this->owner->isDeviceGroup() || $this->owner->isVirtualSystem() )
            $str = $this->owner->getXPath();
        elseif( $this->owner->isPanorama() || $this->owner->isFirewall() )
            $str = '/config/shared';
        else
            derr('unsupported');

        //TODO: intermediate solution
        $str = '/config/devices/entry/network/interface';

        $str = $str.'/ethernet/units';

        return $str;
    }


    private function &getBaseXPath()
    {
        if ($this->owner->isPanorama() ||  $this->owner->isFirewall() )
        {
            $str = "/config/shared";
        }
        else
            $str = $this->owner->getXPath();

        //TODO: intermediate solution
        $str = '/config/devices/entry/network/interface';

        return $str;
    }

    public function &getEthernetIfStoreXPath()
    {
        //Todo: bug available, units only for subinterface
        //$path = $this->getBaseXPath().'/ethernet/units';
        $path = $this->getBaseXPath().'/ethernet';
        return $path;
    }

    public function rewriteXML()
    {
        if( count($this->o) > 0 )
        {
            if( $this->xmlroot === null )
                return;

            $this->xmlroot->parentNode->removeChild($this->xmlroot);
            $this->xmlroot = null;
        }

        if( $this->xmlroot === null )
        {
            if( count($this->o) > 0 )
            {
                $xml = DH::findFirstElementOrCreate('devices', $this->owner->xmlroot);
                $xml = DH::findFirstElementOrCreate('entry', $xml);
                $xml = DH::findFirstElementOrCreate('network', $xml);
                $xml = DH::findFirstElementOrCreate('interface', $xml);
                $xml = DH::findFirstElementOrCreate('ethernet', $xml);

                DH::findFirstElementOrCreate('units', $xml);
                #DH::findFirstElementOrCreate('tag', $this->owner->xmlroot);
            }

        }

        DH::clearDomNodeChilds($this->xmlroot);
        foreach( $this->o as $o)
        {
            if( !$o->isTmp() )
                $this->xmlroot->appendChild($o->xmlroot);
        }
    }
}