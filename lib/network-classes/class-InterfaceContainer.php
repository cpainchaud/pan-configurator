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


/**
 * Class InterfaceContainer
 * @property VirtualSystem $owner
 * @property EthernetInterface[]|LoopbackInterface[]|IPsecTunnel[] $o
 */
class InterfaceContainer extends ObjRuleContainer
{
    /** @var  NetworkPropertiesContainer */
    public $parentCentralStore;

    /**
     * @param VirtualSystem|Zone|VirtualRouter $owner
     * @param NetworkPropertiesContainer $centralStore
     */
    public function __construct($owner, $centralStore)
    {
        $this->owner = $owner;
        $this->parentCentralStore = $centralStore;

        $this->o = Array();
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        foreach($xml->childNodes as $node)
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $interfaceString = $node->textContent;

            $interface = $this->parentCentralStore->findInterfaceOrCreateTmp($interfaceString);

            $this->add($interface);
        }
    }

    /**
     * @return EthernetInterface[]|IPsecTunnel[]|LoopbackInterface[]
     */
    public function interfaces()
    {
        return $this->o;
    }


    /**
     * @param string $ifName
     * @param bool $caseSensitive
     * @return bool
     */
    public function hasInterfaceNamed($ifName, $caseSensitive=true)
    {
        return $this->has($ifName, $caseSensitive);
    }

}