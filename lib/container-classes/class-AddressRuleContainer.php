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
 * Class AddressRuleContainer
 * @property Address[]|AddressGroup[] $o
 * @property Rule|SecurityRule|NatRule $owner
 *
 */
class AddressRuleContainer extends ObjRuleContainer
{
    /** @var null|AddressStore */
    public $parentCentralStore = null;

    // TODO implement 'multicast' support

    public function __construct($owner)
    {
        $this->owner = $owner;
    }


    /**
     * @param Address|AddressGroup $Obj
     * @return bool
     */
    public function addObject( $Obj )
    {
        $this->fasthashcomp = null;

        $ret = parent::add($Obj);

        if( $ret && $this->xmlroot !== null )
        {
            if (count($this->o) > 1)
            {
                DH::createElement($this->xmlroot, 'member', $Obj->name());
            }
            else
            {
                $this->rewriteXML();
            }
        }

        return $ret;
    }

    /**
     * @param Address|AddressGroup $Obj
     * @return bool
     */
    public function API_add( $Obj )
    {
        if( $this->addObject($Obj) )
        {
            $xpath = &$this->getXPath();
            $con = findConnectorOrDie($this);

            if( count($this->o) == 1 )
            {
                $con->sendEditRequest($xpath, $this->getXmlText_inline() );
            }
            else
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
     * @param bool $forceAny
     * @return bool
     */
    public function API_remove( $Obj, $forceAny = false )
    {
        if( $this->remove($Obj, true, $forceAny) )
        {
            $xpath = &$this->getXPath();
            $con = findConnectorOrDie($this);

            if( count($this->o) == 0 )
            {
                $con->sendEditRequest($xpath, $this->getXmlText_inline());
                return true;
            }

            $xpath = $xpath."/member[text()='".$Obj->name()."']";
            $con->sendDeleteRequest($xpath);

            return true;
        }

        return false;
    }


    public function API_sync()
    {
        if( $this->name == 'snathosts' )
        {
            $xpath = DH::elementToPanXPath($this->xmlroot);
        }
        else
        {
            $xpath = &$this->getXPath();
        }
        $con = findConnectorOrDie($this);
        $con->sendEditRequest($xpath, $this->getXmlText_inline());
    }

    public function setAny()
    {
        $this->removeAll();

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
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $content = $node->textContent;

            if( $i == 0 && strtolower($content) == 'any' )
            {
                return;
            }

            if( strlen($content) < 1 )
            {
                derr('this container has members with empty name!', $node);
            }

            $f = $this->parentCentralStore->findOrCreate( $content, $this);
            $this->o[] = $f;
            $i++;
        }
    }


    public function rewriteXML()
    {
        if( $this->xmlroot === null )
            return;

        if( $this->name == 'snathosts' )
        {
            if (count($this->o) == 0 )
                DH::clearDomNodeChilds($this->xmlroot);
            else
            {
                if( $this->owner->natType() == 'static-ip' )
                {
                    DH::clearDomNodeChilds($this->xmlroot);
                    DH::setDomNodeText($this->xmlroot, reset($this->o)->name());
                }
                else
                    DH::Hosts_to_xmlDom($this->xmlroot, $this->o, 'member', false);
            }
        }
        else
            DH::Hosts_to_xmlDom($this->xmlroot, $this->o, 'member', false);
    }

    public function toString_inline()
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
        if( is_object($network) )
            $netStartEnd = $network;
        else
            $netStartEnd = IP4Map::mapFromText($network);

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
     * @param $network string|IP4Map ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
     * @return int
     */
    public function  includesIP4Network($network)
    {
        if( is_object($network) )
            $netStartEnd = $network;
        else
            $netStartEnd = IP4map::mapFromText($network);

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
            while( isset($currentObject->owner) && $currentObject->owner !== null )
            {

                if( isset($currentObject->owner->addressStore) &&
                    $currentObject->owner->addressStore !== null				)
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
            $this->addObject($s);
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


    /**
     * @return string
     */
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
     * @return IP4Map
     */
    public function getIP4Mapping()
    {
        $result = Array( 'unresolved' => Array() );
        $mapObject = new IP4Map();

        foreach( $this->o as $member )
        {
            if( $member->isTmpAddr() && !$member->nameIsValidRuleIPEntry() )
            {
                $result['unresolved'][] = $member;
                continue;
            }
            elseif( $member->isAddress() )
            {
                $localMap = $member->getIP4Mapping();
                $mapObject->addMap($localMap, true);
            }
            elseif( $member->isGroup() )
            {
                $localMap = $member->getIP4Mapping();
                $mapObject->addMap($localMap, true);
            }
            else
                derr('unsupported type of objects '.$member->toString());
        }
        $mapObject->sortAndRecalculate();

        return $mapObject;
    }

    public function copy(AddressRuleContainer $other)
    {
        if( $other->count() == 0 && $this->count() != 0 )
            $this->removeAll();

        foreach( $other->o as $member )
        {
            $this->addObject($member);
        }
    }


    /**
     * @param $zoneIP4Mapping array  array of IP start-end to zone ie  Array( 0=>Array('start'=>0, 'end'=>50, 'zone'=>'internet') 1=>...  )
     * @param $objectIsNegated bool  IP4Mapping of this object will be inverted before doing resolution
     * @return string[] containing zones matched
     */
    public function &calculateZonesFromIP4Mapping( &$zoneIP4Mapping, $objectIsNegated = false)
    {
        $zones = Array();

        $objectsMapping = $this->getIP4Mapping();

        if( $objectIsNegated )
        {
            $fakeMapping= IP4Map::mapFromText('0.0.0.0-255.255.255.255');
            $objectsMapping->substract($fakeMapping);
        }


        foreach( $zoneIP4Mapping as &$zoneMapping )
        {
            $result = $objectsMapping->substractSingleIP4Entry($zoneMapping);

            if( $result != 0 )
            {
                $zones[$zoneMapping['zone']] = $zoneMapping['zone'];
            }

            if( $objectsMapping->count() == 0 )
                break;

        }

        return $zones;
    }

    /**
     * @return Address[]|AddressGroup[]
     */
    public function & membersExpanded($keepGroupsInList=false)
    {
        $localA = Array();

        if( count($this->o) == 0 )
            return $localA;

        foreach( $this->o as $member )
        {
            if( $member->isGroup() )
            {
                $flat = $member->expand($keepGroupsInList);
                $localA = array_merge($localA, $flat);
                if( $keepGroupsInList )
                    $localA[] = $member;
            }
            else
                $localA[] = $member;
        }

        $localA = array_unique_no_cast($localA);

        return $localA;
    }

}





