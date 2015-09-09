<?php
/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud <cpainchaud _AT_ paloaltonetworks.com>
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

class LoopbackInterface
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferencableObject;

    protected $_ipv4Addresses = Array();

    function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
    }


    public function isLoopbackType()
    {
        return true;
    }

    public function load_from_domxml( DOMElement $xml )
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("loopback name name not found\n");

        $ipNode = DH::findFirstElement('ip', $xml);
        if( $ipNode !== false )
        {
            foreach( $ipNode->childNodes as $l3ipNode )
            {
                if( $l3ipNode->nodeType != XML_ELEMENT_NODE )
                    continue;

                $this->_ipv4Addresses[] = $l3ipNode->getAttribute('name');
            }
        }


    }

    public function getIPv4Addresses()
    {
        return $this->_ipv4Addresses;
    }

}