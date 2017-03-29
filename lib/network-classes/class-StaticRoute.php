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


class StaticRoute
{
    use XmlConvertible;
    use PathableName;
    use ReferencableObject;

    /** @var string */
    protected $_destination;

    protected $_nexthopType = 'none';

    protected $_nexthopIP = null;

    /** @var null|string  */
    protected $_nexthopVR = null;

    /** @var VirtualRouter */
    public $owner;

    /** @var null|EthernetInterface|AggregateEthernetInterface|TmpInterface */
    protected $_interface = null;


    /**
     * StaticRoute constructor.
     * @param string $name
     * @param VirtualRouter $owner
     */
    function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
    }

    /**
     * @param $xml DOMElement
     */
    function load_from_xml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("static-route name not found\n");

        $dstNode = DH::findFirstElementOrDie('destination', $xml);
        $this->_destination = $dstNode->textContent;

        $ifNode = DH::findFirstElement('interface', $xml);
        if( $ifNode !== false )
        {
            $this->_interface = $this->owner->owner->owner->network->findInterfaceOrCreateTmp($ifNode->textContent);
        }

        $fhNode = DH::findFirstElement('nexthop', $xml);
        if( $fhNode !== false )
        {
            $fhTypeNode = DH::findFirstElement('ip-address', $fhNode);
            if( $fhTypeNode !== false )
            {
                $this->_nexthopType = 'ip-address';
                $this->_nexthopIP = $fhTypeNode->textContent;
                return;
            }
            $fhTypeNode = DH::findFirstElement('next-vr', $fhNode);
            if( $fhTypeNode !== false )
            {
                $this->_nexthopType = 'next-vr';
                $this->_nexthopVR = $fhTypeNode->textContent;
                return;
            }

        }
    }

    /**
     * @return string
     */
    public function destination()
    {
        return $this->_destination;
    }

    /**
     * @return bool|string
     */
    public function destinationIP4Mapping()
    {
        return cidr::stringToStartEnd($this->_destination);
    }

    public function nexthopIP()
    {
        return $this->_nexthopIP;
    }

    /**
     * @return null|string
     */
    public function nexthopVR()
    {
        return $this->_nexthopVR;
    }

    public function nexthopInterface()
    {
        return $this->_interface;
    }


    /**
     * @return string   'none','ip-address'
     */
    public function nexthopType()
    {
        return $this->_nexthopType;
    }

}