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
/**
 * Class AddressRuleContainer
 * @property Address[]|AddressGroup[] $o
 * @property Rule|SecurityRule|NatRule $owner
 *
 */
class AddressRuleContainer extends ObjRuleContainer
{
    /**
     * @var null|string[]|DOMElement
     */
    public $xmlroot=null;

    /**
     * @var null|AddressStore
     */
    public $parentCentralStore = null;

    // TODO implement 'multicast' support

    public function AddressRuleContainer($owner)
    {
        $this->owner = $owner;
        $this->o = Array();

        $this->findParentCentralStore();
    }

    /**
     * @param Address|AddressGroup $Obj
     * @param bool $rewriteXml
     * @return bool
     */
    public function add( $Obj, $rewriteXml = true )
    {
        $this->fasthashcomp = null;

        $ret = parent::add($Obj);
        if( $ret && $rewriteXml )
        {
            $this->rewriteXML();
        }
        return $ret;
    }

    /**
     * @param Address|AddressGroup $Obj
     * @param bool $rewritexml
     * @return bool
     */
    public function API_add( $Obj, $rewritexml = true )
    {
        if( $this->add($Obj, $rewritexml) )
        {
            $xpath = &$this->getXPath();
            $con = findConnectorOrDie($this);

            if( count($this->o) == 1 )
            {
                $url = "type=config&action=delete&xpath=" . $xpath;
                $con->sendRequest($url);
            }

            $con->sendSetRequest($xpath, "<member>{$Obj->name()}</member>");

            return true;
        }

        return false;
    }


    /**
     * @param Address|AddressGroup $Obj
     * @param bool $rewriteXml
     * @param bool $forceAny
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function remove( $Obj, $rewriteXml = true, $forceAny = false )
    {
        $count = count($this->o);

        $ret = parent::remove($Obj);

        if( $ret && $count == 1 && !$forceAny  )
        {
            derr("you are trying to remove last Object from a rule which will set it to ANY, please use forceAny=true for object: "
                .$this->toString() ) ;
        }

        if( $ret && $rewriteXml )
        {
            $this->rewriteXML();
        }
        return $ret;
    }

    /**
     * @param Address|AddressGroup $Obj
     * @param bool $rewriteXml
     * @param bool $forceAny
     * @return bool
     */
    public function API_remove( $Obj, $rewriteXml = true, $forceAny = false )
    {
        if( $this->remove($Obj, $rewriteXml, $forceAny) )
        {
            $xpath = &$this->getXPath();
            $con = findConnectorOrDie($this);

            if( count($this->o) == 0 )
            {
                $url = "type=config&action=delete&xpath=" . $xpath;
                $con->sendRequest($url);
                $url = "type=config&action=set&xpath=$xpath&element=<member>any</member>";
                $con->sendRequest($url);
                return true;
            }

            $url = "type=config&action=delete&xpath=" . $xpath."/member[text()='".$Obj->name()."']";
            $con->sendRequest($url);

            return true;
        }

        return false;
    }

    public function setAny()
    {
        foreach( $this->o as $o )
        {
            $this->remove($o, false, true);
        }

        $this->rewriteXML();
    }

    /**
     * @param Address|AddressGroup|string $object can be Address|AddressGroup object or object name (string)
     * @return bool
     */
    public function has( $object, $caseSensitive = true )
    {
        return parent::has($object, $caseSensitive);
    }



    /**
     * return an array with all objects
     * @return Address[]|AddressGroup[]
     */
    public function members()
    {
        return $this->o;
    }

    /**
     * return an array with all objects
     * @return Address[]|AddressGroup[]
     */
    public function all()
    {
        return $this->o;
    }
    

    /**
     * should only be called from a Rule constructor
     * @ignore
     */
    public function load_from_domxml($xml)
    {
        //print "started to extract '".$this->toString()."' from xml\n";
        $this->xmlroot = $xml;
        $i=0;
        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 ) continue;

            if( $i == 0 && strtolower($node->textContent) == 'any' )
            {
                return;
            }

            $f = $this->parentCentralStore->findOrCreate( $node->textContent, $this);
            $this->o[] = $f;
            $i++;
        }
    }


    public function rewriteXML()
    {
        if( $this->xmlroot === null )
            return;

        if( $this->xmlroot !== null && $this->name == 'snathosts' && count($this->o) == 0 )
            DH::clearDomNodeChilds($this->xmlroot);
        else
            DH::Hosts_to_xmlDom($this->xmlroot, $this->o, 'member', true);
    }

    public function &toString_inline()
    {
        if( count($this->o) == 0 )
        {
            $out = '**ANY**';
            return $out;
        }

        $out = parent::toString_inline();
        return $out;
    }

    /**
     * return 0 if not match, 1 if this object is fully included in $network, 2 if this object is partially matched by $ref.
     * Always return 0 (not match) if this is object = ANY
     * @param string $network ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
     * @return int
     */
    public function  includedInIP4Network($network)
    {
        if( is_array($network) )
            $netStartEnd = &$network;
        else
            $netStartEnd = cidr::stringToStartEnd($network);

        if( count($this->o) == 0 )
            return 0;

        $result = -1;

        foreach( $this->o as $o )
        {
            $localResult =  $o->includedInIP4Network($netStartEnd);
            if( $localResult == 1 )
            {
                if( $result == 2 )
                    continue;
                if( $result == -1 )
                    $result = 1;
                else if( $result == 0 )
                    return 2;
            }
            elseif( $localResult == 2 )
            {
                return 2;
            }
            elseif( $localResult == 0 )
            {
                if( $result == -1 )
                    $result = 0;
                else if( $result == 1 )
                    return 2;
            }
        }

        return $result;
    }

    /**
     * return 0 if not match, 1 if $network is fully included in this object, 2 if $network is partially matched by this object.
     * @param $network ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
     * @return int
     */
    public function  includesIP4Network($network)
    {
        if( is_array($network) )
            $netStartEnd = &$network;
        else
            $netStartEnd = cidr::stringToStartEnd($network);

        if( count($this->o) == 0 )
            return 0;

        $result = -1;

        foreach( $this->o as $o )
        {
            $localResult =  $o->includesIP4Network($netStartEnd);
            if( $localResult == 1 )
            {
                return 1;
            }
            elseif( $localResult == 2 )
            {
                $result = 2;
            }
            elseif( $localResult == 0 )
            {
                if( $result == -1 )
                    $result = 0;
            }
        }

        return $result;
    }


    /**
     *
     * @ignore
     */
    protected function findParentCentralStore()
    {
        $this->parentCentralStore = null;

        if( $this->owner )
        {
            $currentObject = $this;
            while( isset($currentObject->owner) && !is_null($currentObject->owner) )
            {

                if( isset($currentObject->owner->addressStore) &&
                    !is_null($currentObject->owner->addressStore)				)
                {
                    $this->parentCentralStore = $currentObject->owner->addressStore;
                    //print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
                    return;
                }
                $currentObject = $currentObject->owner;
            }
        }

        mwarning('no parent store found!');

    }


    /**
     * Merge this set of objects with another one (in paramater). If one of them is 'any'
     * then the result will be 'any'.
     *
     */
    public function merge($other)
    {
        $this->fasthashcomp = null;

        // This is Any ? then merge = Any
        if( count($this->o) == 0 )
            return;

        // this other is Any ? then this one becomes Any
        if( count($other->o) == 0 )
        {
            $this->setAny();
            return;
        }

        foreach($other->o as $s)
        {
            $this->add($s);
        }

    }

    /**
     * To determine if a container has all the zones from another container. Very useful when looking to compare similar rules.
     * @param $other
     * @param $anyIsAcceptable
     * @return boolean true if Zones from $other are all in this store
     */
    public function includesContainer(AddressRuleContainer $other, $anyIsAcceptable=true )
    {

        if( !$anyIsAcceptable )
        {
            if( $this->count() == 0 || $other->count() == 0 )
                return false;
        }

        if( $this->count() == 0 )
            return true;

        if( $other->count() == 0 )
            return false;

        $objects = $other->members();

        foreach( $objects as $o )
        {
            if( !$this->has($o) )
                return false;
        }

        return true;

    }

    public function API_setAny()
    {
        $this->setAny();
        $xpath = &$this->getXPath();
        $con = findConnectorOrDie($this);

        $url = "type=config&action=delete&xpath=".$xpath;
        $con->sendRequest($url);

        $url = "type=config&action=set&xpath=$xpath&element=<member>any</member>";
        $con->sendRequest($url);
    }


    public function &getXPath()
    {

        $str = $this->owner->getXPath().'/'.$this->name;

        return $str;

    }

    /**
     * @return bool
     */
    public function isAny()
    {
        return ( count($this->o) == 0 );
    }


    /**
     * @param Address|AddressGroup
     * @param bool $anyIsAcceptable
     * @return bool
     */
    public function hasObjectRecursive( $object, $anyIsAcceptable=false)
    {
        if( $object === null )
            derr('cannot work with null objects');

        if( $anyIsAcceptable && $this->count() == 0 )
            return false;

        foreach( $this->o as $o )
        {
            if( $o === $object )
                return true;
            if( $o->isGroup() )
                if( $o->hasObjectRecursive($object) ) return true;
        }

        return false;
    }


    /**
     * To determine if a store has all the Address from another store, it will expand AddressGroups instead of looking for them directly. Very useful when looking to compare similar rules.
     * @param AddressRuleContainer $other
     * @param bool $anyIsAcceptable if any of these objects is Any the it will return false
     * @return bool true if Address objects from $other are all in this store
     */
    public function includesContainerExpanded(AddressRuleContainer $other, $anyIsAcceptable=true )
    {

        if( !$anyIsAcceptable )
        {
            if( $this->count() == 0 || $other->count() == 0 )
                return false;
        }

        if( $this->count() == 0 )
            return true;

        if( $other->count() == 0 )
            return false;

        $localA = Array();
        $A = Array();

        foreach( $this->o as $object )
        {
            if( $object->isGroup() )
            {
                $flat = $object->expand();
                $localA = array_merge($localA, $flat);
            }
            else
                $localA[] = $object;
        }
        $localA = array_unique_no_cast($localA);

        $otherAll = $other->all();

        foreach( $otherAll as $object )
        {
            if( $object->isGroup() )
            {
                $flat = $object->expand();
                $A = array_merge($A, $flat);
            }
            else
                $A[] = $object;
        }
        $A = array_unique_no_cast($A);

        $diff = array_diff_no_cast($A, $localA);

        if( count($diff) > 0 )
        {
            return false;
        }


        return true;

    }

    /**
     * @return array  result['map'][] will contain all mapping in form of an array['start'] and ['end]. result['unresolved'][] will provide a list unresolved objects
     */
    public function & getIP4Mapping()
    {
        $result = Array( 'unresolved' => Array() );
        $map = Array();

        foreach( $this->o as $member )
        {
            if( $member->isTmpAddr() )
            {
                $result['unresolved'][] = $member;
                continue;
            }
            elseif( $member->isAddress() )
            {
                $type = $member->type();

                if ($type != 'ip-netmask' && $type != 'ip-range')
                {
                    $result['unresolved'][] = $member;
                    continue;
                }
                $map[] = $member->resolveIP_Start_End();
            }
            elseif( $member->isGroup() )
            {
                $subMap = $member->getIP4Mapping();
                foreach( $subMap['map'] as &$subMapRecord )
                {
                    $map[] = &$subMapRecord;
                }
                unset($subMapRecord);
                foreach( $subMap['unresolved'] as $subMapRecord )
                {
                    $result['unresolved'][] = $subMapRecord;
                }

            }
            else
                derr('unsupported type of objects '.$member->toString());
        }

        $map = mergeOverlappingIP4Mapping($map);

        $result['map'] = &$map;

        return $result;
    }


    /**
     * @param $zoneIP4Mapping array
     * @return array
     */
    public function &calculateZonesFromIP4Mapping( &$zoneIP4Mapping, $objectIsNegated )
    {
        $zones = Array();

        $objectsMapping = &$this->getIP4Mapping();

        if( $objectIsNegated )
        {
            $fakeMapping= Array();
            $fakeMapping['map'][] = Array( 'start' => 0 , 'end' => 4294967295) ;
            foreach( $objectsMapping['map'] as &$entry )
                removeNetworkFromIP4Mapping($fakeMapping['map'], $entry);
            $objectsMapping = &$fakeMapping;
        }


        foreach( $zoneIP4Mapping as &$zoneMapping )
        {
            $result = removeNetworkFromIP4Mapping($objectsMapping['map'], $zoneMapping);

            if( $result != 0 )
            {
                $zones[$zoneMapping['zone']] = $zoneMapping['zone'];
            }

            if( count($objectsMapping) == 0 )
                break;

        }

        return $zones;
    }

}





