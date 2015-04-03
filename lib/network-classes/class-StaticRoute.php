<?php
/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud cpainchaud _AT_ paloaltonetworks.com
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
    use ReferencableObject;
    use PathableName;

    /**
     * @var string
     */
    protected $_destination;

    protected $_nexthopType = 'tmp';

    protected $_nexthopIP = null;

    /** @property $owner VirtualRouter */

    function StaticRoute($name, $owner)
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
        $_destination = $dstNode->textContent;

        $fhNode = DH::findFirstElementOrDie('nexthop', $xml);

        $fhTypeNode = DH::findFirstElement('ip-address', $fhNode);
        if( $fhTypeNode !== false )
        {
            $this->_nexthopType = 'ip-address';
            $this->_nexthopIP = $fhTypeNode->textContent;
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
        return cidr::cidr2netmask($this->_destination);
    }

    public function nexthopIP()
    {
        return $this->_nexthopIP;
    }

    public function nexthopIP4Mapping()
    {
        return cidr::cidr2netmask($this->_nexthopIP);
    }

}