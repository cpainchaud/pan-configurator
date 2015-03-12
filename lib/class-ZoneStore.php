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
 * Class ZoneStore
 *
 * @property ZoneStore $parentCentralStore
 * @property Zone[] $o
 *
 */
class ZoneStore extends ObjStore
{
	public $xmlroot=null;
	
	public $parentCentralStore = null;
	
	public static $childn = 'Zone';

    /**
     * @param VirtualSystem|DeviceGroup|PanoramaConf $owner
     */
	public function ZoneStore($owner)
	{
		$this->classn = &self::$childn;
		
		$this->owner = $owner;
		$this->o = Array();
		
		$this->findParentCentralStore();
	}
	
	
	/**
	* looks for a zone named $name ,return that Zone object, null if not found
	* @param string $name
	* @return Zone
	*/
	public function find($name, $ref=null)
	{
		return $this->findByName($name,$ref);
	}
	
	
	/**
	* add a Zone to this store. Use at your own risk.
     * @param Zone
	* @param bool
	* @return bool
	*/
	public function addZone( Zone $Obj, $rewriteXML = true )
	{
		$fasthashcomp=null;

		$ret = $this->add($Obj);
		if( $ret && $rewriteXML )
		{
			$this->rewriteXML();
		}
		return $ret;			
	}


	/**
	* remove a Zone a Zone to this store.
     * @param Zone
	* @param bool $rewriteXML
	*
	* @return bool  True if Zone was found and removed. False if not found.
	*/
	public function removeZone( Zone $Obj, $rewriteXML = true )
	{
		$ret = $this->remove($Obj);

		if( $ret && $rewriteXML )
		{
			$this->rewriteXML();
		}

		return $ret;			
	}

    /**
     * @param Zone|string $zone can be Zone object or zone name (string). this is case sensitive
     * @return bool
     */
    public function hasZoneNamed( $zone, $caseSensitive = true )
    {
        return $this->has($zone, $caseSensitive);
    }


	
	/**
	* return an array with all Zones in this store
	* @return Zone[]
	*/
	public function zones()
	{
		return $this->o;
	}
	
	
	public function rewriteXML()
	{
        if( $this->xmlroot !== null )
        {
            DH::clearDomNodeChilds($this->xmlroot);
            foreach( $this->o as $zone )
            {
                if( ! $zone->isTmp() )
                    $this->xmlroot->appendChild($zone->xmlroot);
            }
        }
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
			$curo = $this;
			while( isset($curo->owner) && !is_null($curo->owner) )
			{
				
				if( isset($curo->owner->zoneStore) &&
					!is_null($curo->owner->zoneStore)				)
				{
					$this->parentCentralStore = $curo->owner->zoneStore;
					//print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
					return;
				}
				$curo = $curo->owner;
			}
		}
		
		//print $this->toString().": no parent store found\n";

	}


    public function &getXPath()
    {
        if( $this->xmlroot === null )
            derr('unsupported on virtual Stores');

        $xpath = $this->owner->getXPath()."/zone/";

        return $xpath;

    }


}


trait centralZoneStore
{
    /**
     * @var ZoneStore
     */
	public $zoneStore=null;
	
	public function zoneStore()
	{
		return $this->zoneStore;
	}
}


