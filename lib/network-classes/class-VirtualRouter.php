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

class VirtualRouter
{
    use XmlConvertible;
    use PathableName;
    use ReferencableObject;

    /**
     * @var VirtualRouterStore
     */
    public $owner;

    /**
     * @var StaticRoute[]
     */
    protected $_staticRoutes = Array();

    /** @var InterfaceContainer */
    public $attachedInterfaces;

    /**
     * @param $name string
     * @param $owner PANConf
     */
    public function VirtualRouter($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;

        $this->attachedInterfaces = new InterfaceContainer($this, $owner->network);
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

        $node = DH::findFirstElementOrCreate('interface', $xml);

        $this->attachedInterfaces->load_from_domxml($node);

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
     * @return VirtualSystem[]
     */
    public function & findConcernedVsys()
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
     * @param $contextVSYS VirtualSystem
     * @param $orderByNarrowest bool
     * @return array
     */
    public function getIPtoZoneRouteMapping($contextVSYS, $orderByNarrowest=true )
    {
        $ipv4 = Array();
        $ipv6 = Array();

        $ipv4sort = Array();

        foreach( $this->staticRoutes() as $route )
        {
            $ipv4Mapping = $route->destinationIP4Mapping();

            $nexthopIf = $route->nexthopInterface();
            if( $nexthopIf !== null )
            {
                if( !$this->attachedInterfaces->hasInterfaceNamed($nexthopIf->name()) )
                {
                    mwarning("route {$route->name()}/{$route->destination()} ignored because its attached to interface {$nexthopIf->name()} but this interface does not belong to this virtual router'");
                    continue;
                }
                if( $contextVSYS->importedInterfaces->hasInterfaceNamed($nexthopIf->name()) )
                {
                    $findZone = $contextVSYS->zoneStore->findZoneMatchingInterfaceName($nexthopIf->name());
                    if( $findZone === null )
                    {
                        mwarning("route {$route->name()}/{$route->destination()} ignored because its attached to interface {$nexthopIf->name()} but this interface is not attached to a Zone in vsys {$contextVSYS->name()}'");
                        continue;
                    }
                    else
                    {
                        $record = Array( 'network' => $route->destination(), 'start' => $ipv4Mapping['start'], 'end' => $ipv4Mapping['end'], 'zone' => $findZone->name(), 'origin' => 'static', 'priority' => 2);
                        $ipv4sort[ $record['end']-$record['start'] ][$record['start']][] = &$record;
                        unset($record);
                    }
                }
                else
                {
                    $findVsys = $contextVSYS->owner->network->findVsysInterfaceOwner($nexthopIf->name());

                    if( $findVsys === null )
                    {
                        mwarning("route {$route->name()}/{$route->destination()} ignored because its attached to interface {$nexthopIf->name()} but this interface is attached to no VSYS");
                        continue;
                    }
                    $externalZone = $contextVSYS->zoneStore->findZoneWithExternalVsys($findVsys);

                    if( $externalZone == null )
                    {
                        mwarning("route {$route->name()}/{$route->destination()} ignored because its attached to interface {$nexthopIf->name()} but this interface is attached to wrong vsys '{$findVsys->name()}' and no external zone could be found");
                        continue;
                    }

                    $record = Array( 'network' => $route->destination(), 'start' => $ipv4Mapping['start'], 'end' => $ipv4Mapping['end'], 'zone' => $externalZone->name(), 'origin' => 'static', 'priority' => 2);
                    $ipv4sort[ $record['end']-$record['start'] ][$record['start']][] = &$record;
                    unset($record);
                }

            }
            else if( $route->nexthopType() == 'ip-address' )
            {
                $nextHopType = $route->nexthopType();
                $nexthopIP = $route->nexthopIP();
                $findZone = null;
                foreach($this->attachedInterfaces->interfaces() as $if )
                {
                    if( ($if->isEthernetType()|| $if->isAggregateType()) && $if->type() == 'layer3' || $if->isLoopbackType() )
                    {
                        if( ! $contextVSYS->importedInterfaces->hasInterfaceNamed($if->name()) )
                            continue;

                        if( $if->isLoopbackType() )
                            $ips = $if->getIPv4Addresses();
                        else
                            $ips = $if->getLayer3IPv4Addresses();

                        foreach( $ips as &$interfaceIP )
                        {
                            if( cidr::netMatch($nexthopIP, $interfaceIP) > 0 )
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
                        if( $findZone !== null)
                        {
                            break;
                        }
                    }
                    else
                    {
                        continue;
                    }
                }
                if( $findZone === null )
                {
                    mwarning("route {$route->name()}/{$route->destination()} ignored because no matching interface was found for nexthop={$nexthopIP}");
                    continue;
                }

                $record = Array( 'network' => $route->destination(), 'start' => $ipv4Mapping['start'], 'end' => $ipv4Mapping['end'], 'zone' => $findZone->name(), 'origin' => 'static', 'priority' => 2);
                $ipv4sort[ $record['end']-$record['start'] ][$record['start']][] = &$record;
                unset($record);
            }
            else
            {
                mwarning("route {$route->name()}/{$route->destination()} ignored because of unknown type '{$nextHopType}'");
                continue;
            }
        }

        foreach( $this->attachedInterfaces->interfaces() as $if )
        {
            if( ! $contextVSYS->importedInterfaces->hasInterfaceNamed($if->name()) )
                continue;

            if( ($if->isEthernetType() || $if->isAggregateType()) && $if->type() == 'layer3' )
            {
                $findZone = $contextVSYS->zoneStore->findZoneMatchingInterfaceName($if->name());
                if( $findZone === null )
                    continue;

                $ipAddresses = $if->getLayer3IPv4Addresses();

                foreach( $ipAddresses as $interfaceIP )
                {
                    $ipv4Mapping = cidr::stringToStartEnd($interfaceIP);
                    $record = Array('network' => $interfaceIP, 'start' => $ipv4Mapping['start'], 'end' => $ipv4Mapping['end'], 'zone' => $findZone->name(), 'origin' => 'connected', 'priority' => 1);
                    $ipv4sort[$record['end'] - $record['start']][$record['start']][] = &$record;
                    unset($record);
                }
            }
            elseif( $if->isLoopbackType() )
            {
                $findZone = $contextVSYS->zoneStore->findZoneMatchingInterfaceName($if->name());
                if( $findZone === null )
                    continue;

                $ipAddresses = $if->getIPv4Addresses();

                foreach( $ipAddresses as $interfaceIP )
                {
                    $ipv4Mapping = cidr::stringToStartEnd($interfaceIP);
                    $record = Array('network' => $interfaceIP, 'start' => $ipv4Mapping['start'], 'end' => $ipv4Mapping['end'], 'zone' => $findZone->name(), 'origin' => 'connected', 'priority' => 1);
                    $ipv4sort[$record['end'] - $record['start']][$record['start']][] = &$record;
                    unset($record);
                }
            }
        }

        ksort($ipv4sort);

        foreach( $ipv4sort as &$record )
        {
            ksort($record);
            foreach( $record as &$subRecord )
            {
                foreach($subRecord as &$subSubRecord)
                {
                    $ipv4[] = &$subSubRecord;
                }
            }
        }


        $result = Array('ipv4' => &$ipv4 , 'ipv6' => &$ipv6);

        return $result;
    }


}