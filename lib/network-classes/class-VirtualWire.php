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

class VirtualWire
{
    use XmlConvertible;
    use PathableName;
    use ReferencableObject;

    /** @var VirtualWireStore */
    public $owner;

    /** @var InterfaceContainer */
    public $attachedInterface1;

    /** @var InterfaceContainer */
    public $attachedInterface2;
    /**
     * @param $name string
     * @param $owner VirtualWireStore
     */
    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
    }

    /**
     * @param DOMElement $xml
     */
    public function load_from_domxml( $xml )
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("virtual-wire name not found\n");

        $tmp_int1 = DH::findFirstElement('interface1', $xml);
        $tmp_int2 = DH::findFirstElement('interface2', $xml);

        if( is_object($tmp_int1)  )
            $this->attachedInterface1 = $tmp_int1->textContent;
        if( is_object($tmp_int2)  )
            $this->attachedInterface2 = $tmp_int2->textContent;
    }


    /**
     * @return VirtualSystem[]
     */
    public function &findConcernedVsys()
    {
        $vsysList = Array();
        foreach($this->attachedInterfaces->interfaces() as $if )
        {
            $vsys = $this->owner->owner->network->findVsysInterfaceOwner($if->name());
            if( $vsys !== null )
                $vsysList[$vsys->name()] = $vsys;
        }

        return $vsysList;
    }

    /**
     * return true if change was successful false if not
     * @return bool
     * @param string $name new name for the VirtualWire
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
    /**
     * return true if change was successful false if not
     * @return bool
     * @param string $int_num name for the VirtualWire interface
     * @param ethernetInterface $if interface for the VirtualWire interface
     */
    public function setInterface( $int_num, $if )
    {
        if( $this->attachedInterface1 == $if->name() || $this->attachedInterface2 == $if->name() )
            return true;

        $tmp_xmlroot = $this->xmlroot;

        if( $int_num == "interface1" )
        {
            $this->attachedInterface1 = $if->name();
            $tmp_int = DH::findFirstElementOrCreate('interface1', $tmp_xmlroot);
        }
        elseif( $int_num == "interface2" )
        {
            $this->attachedInterface2 = $if->name();
            $tmp_int = DH::findFirstElementOrCreate('interface2', $tmp_xmlroot);
        }
        else
            return false;

        DH::setDomNodeText($tmp_int, $if->name());

        return true;
    }

    /**
     * Add a ip to this interface, it must be passed as an object or string
     * @param Address $ip Object to be added, or String
     * @return bool
     */
    public function API_setInterface($int_num, $if)
    {
        $ret = $this->setInterface($int_num, $if);

        if( $ret )
        {
            $con = findConnector($this);
            $xpath = $this->getXPath();

            $con->sendSetRequest($xpath, "<".$int_num.">{$if->name()}</".$int_num.">");
        }

        return $ret;
    }

    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getEthernetIfStoreXPath()."/entry[@name='".$this->name."']";

        return $str;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

}
