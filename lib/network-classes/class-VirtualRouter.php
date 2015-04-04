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

class VirtualRouter
{
    use ReferencableObject;
    use PathableName;

    /**
     * @var VirtualRouterStore
     */
    public $owner;

    /**
     * @var StaticRoute[]
     */
    protected $_staticRoutes = Array();

    protected $_attachedInterfaces = Array();

    /**
     * @param $name string
     * @param $owner PANConf
     */
    public function VirtualRouter($name, $owner)
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
            derr("virtual-router name not found\n");

        $node = DH::findXPath('/routing-table/ip/static-route/entry',$xml);

        if( $node !== false )
        {
            for( $i=0; $i < $node->length; $i++ )
            {
                $newRoute = new StaticRoute('***tmp**', $this);
                $newRoute->load_from_xml($node->item($i));
                $this->_staticRoutes[] = $newRoute;
            }
        }
    }


    /**
     * @return StaticRoute[]
     */
    public function staticRoutes()
    {
        return $this->_staticRoutes;
    }


    /**
     * @param $vsysContext VirtualSystem
     */
    public function getRouteResolutionIPMap($vsysContext)
    {

    }




}