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

    /** @var EthernetInterface[]|TmpInterface[] */
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

        $nodeList = DH::findXPath('/interface/member',$xml);

        for($i=0; $i<$nodeList->length;$i++)
        {
            $findInterface = $this->owner->owner->network->findInterfaceOrCreateTmp($nodeList->item($i)->textContent);
            $this->_attachedInterfaces[$findInterface->name()] = $findInterface;
        }

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
     * @param $contextVSYS VirtualSystem
     * @param $orderByNarrowest bool
     * @return array
     */
    public function getIPtoZoneRouteMapping($contextVSYS, $orderByNarrowest=true )
    {
        $interfaces  = $this->owner->owner->network->findInterfaceAttachedToVSYS($contextVSYS);

        $ipv4 = Array();
        $ipv6 = Array();

        $ipv4sort = Array();

        foreach( $this->staticRoutes() as $route )
        {
            $ipv4Mapping = $route->destinationIP4Mapping();

            $nexthopIf = $route->nexthopInterface();
            if( $nexthopIf !== null )
            {
                if( !isset($this->_attachedInterfaces[$nexthopIf->name()]) )
                {
                    mwarning("route {$route->name()}/{$route->destination()} ignored because its attached to interface {$nexthopIf->name()} but this interface does not belong to this virtual router'");
                    continue;
                }
                if( isset($interfaces[$nexthopIf->name()]) )
                {
                    $findZone = $contextVSYS->zoneStore->findZoneMatchingInterfaceName($nexthopIf->name());
                    if( $findZone === null )
                    {
                        mwarning("route {$route->name()}/{$route->destination()} ignored because its attached to interface {$nexthopIf->name()} but this interface is not attached to a Zone in vsys {$contextVSYS->name()}'");
                        continue;
                    }
                }
                else
                {
                    mwarning("route {$route->name()}/{$route->destination()} ignored because its attached to interface {$nexthopIf->name()} but this interface is attached to wrong vsys '{$contextVSYS->name()}'");
                    continue;
                }

            }
            $nextHopType = $route->nexthopType();

            if( $nextHopType == 'ip-address' )
            {
                $nexthopIP = $route->nexthopIP();
                foreach($this->_attachedInterfaces as $if )
                {
                    if( ($if->isEthernetType()|| $if->isAggregateType()) && $if->type() == 'layer3' )
                    {
                        if( $if->importedByVSYS !== $contextVSYS )
                            continue;
                        $ips = $if->getLayer3IPv4Addresses();
                        foreach( $ips as &$ip )
                        {
                            if( cidr::netMatch($ip, $nexthopIP) > 0 )
                            {
                                $findZone = $contextVSYS->zoneStore->findZoneMatchingInterfaceName($if->name());
                                if( $findZone === null )
                                {
                                    mwarning("route {$route->name()}/{$route->destination()} ignored because its attached to interface {$if->name()} but this interface is not attached to a Zone in vsys {$contextVSYS->name()}'");
                                    continue;
                                }

                                break;
                            }
                        }
                    }
                    else
                    {
                        continue;
                    }
                }
                mwarning("route {$route->name()}/{$route->destination()} ignored because no matching interface was found for nexthop={$nexthopIP}");
                continue;
            }
            else
            {
                mwarning("route {$route->name()}/{$route->destination()} ignored because of unknown type '{$nextHopType}'");
                continue;
            }

            $record = Array( 'network' => $route->destination(), 'start' => $ipv4Mapping['start'], 'end' => $ipv4Mapping['end'], 'zone' => $findZone->name());
            $ipv4sort[ $record['end']-$record['start'] ][] = &$record;
            //$ipv4sort = &$record;
            unset($record);
        }

        krsort($ipv4sort);

        foreach( $ipv4sort as &$record )
        {
            foreach( $record as &$subRecord )
            {
                $ipv4[] = &$subRecord;
            }
        }


        $result = Array('ipv4' => &$ipv4 , 'ipv6' => &$ipv6);

        return $result;
    }




}