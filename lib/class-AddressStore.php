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
 * Class AddressStore
 * @property string $name
 * @property PanAPIConnector $con
 */
class AddressStore
{
	use PathableName;

    /**
     * @var VirtualSystem|DeviceGroup|PanoramaConf|PANConf|null
     */
	public $owner;
	
	protected $centralStore = false;

	/**
	 * @var null|AddressStore
	 */
	public $parentCentralStore = null;

    /**
     * @var Address[]|AddressGroup[]
     */
	protected $all = Array();

	/**
	 * @var Address[]
	 */
	protected $addr = Array();


	/**
	 * @var Address[]
	 */
	protected $tmpaddr = Array();


	/**
	 * @var AddressGroup[]
	 */
	protected $addrg = Array();

    /**
     * @var string[]|DOMElement
     */
	public $addrroot;

    /**
     * @var string[]|DOMElement
     */
	public $addrgroot;

    /**
     * @var null|string[]|DOMElement
     */
	public $xmlroot = null;
	
	public $fasthashcomp = null;
	
	
	public function AddressStore($owner, $centralRole=false)
	{
		
		$this->owner = $owner;
		$this->centralStore = $centralRole;
		$this->findParentCentralStore();

		if( $this->centralStore )
		{
			$this->addr = Array();
			$this->addrg = Array();
			$this->tmpaddr = Array();
		}
			
	}

	private function &getBaseXPath()
	{
		$str = '';

		$class = get_class($this->owner);

		if ($class == 'PanoramaConf' ||  $class == 'PANConf' )
		{
			$str = "/config/shared";
		}
		else
			$str = $this->owner->getXPath();


        return $str;
	}

	public function &getAddressStoreXPath()
	{
		if( !$this->centralStore )
			derr('cannot be called from a non central store object');
		$path = $this->getBaseXPath().'/address';
		return $path;
	}

	public function &getAddressGroupStoreXPath()
	{
		if( !$this->centralStore )
			derr('cannot be called from a non central store object');
		$path = $this->getBaseXPath().'/address-group';
		return $path;
	}
	
	
	
	/**
	* For developper use only
	*
	*/
	public function load_addresses_from_domxml($xml)
	{
		$this->fasthashcomp = null;
		
		$this->addrroot = $xml;
		
		foreach( $this->addrroot->childNodes as $node )
		{
			if( $node->nodeType != 1 ) continue;

			$ns = new Address('',$this);
			$ns->load_from_domxml($node);
			//print $this->toString()." : new service '".$ns->name()."' created\n";

			$lower = strtolower($ns->name());

			if( $this->centralStore )
			{
				$this->addr[$lower] = $ns;
			}
			$this->all[$lower] = $ns;
		}
	}


	/*private function remergeAll()
	{
		$this->all = array_merge($this->addr, $this->addrg, $this->tmpaddr);
		
		
		$this->regen_Indexes();
	}*/
	
	/**
	* Returns an Array with all Address , AddressGroups, TmpAddress objects in this store
	*
	*/
	public function all()
	{
		return $this->all;
	}


	public function load_addressgroups_from_domxml($xml)
	{
		$this->fasthashcomp = null;
		
		$this->addrgroot = $xml;
		
		foreach( $xml->childNodes as $node )
		{
			if( $node->nodeType != 1 ) continue;

			$ns = new AddressGroup('',$this);
			$ns->load_from_domxml($node);
			
			$f = $this->findTmpAddress($ns->name(), null,false);
			if( $f )
			{
				$f->replaceMeGlobally($ns);
				$this->remove($f, false);
				
			}

			$lower = strtolower($ns->name());

			if( $this->centralStore )
			{
				$this->addrg[$lower] = $ns;
			}
			
			$this->all[$lower] = $ns;
		}
	}
	


	/**
	* For developper use only
	* @param Address|Addressgroup $current
     * @param Address|AddressGroup|null $newObject
	*/
	public function replaceHostObject($current, $newObject)
	{
		if( $this->centralStore )
		{
			return;
		}

		if( $this->inStore($current) )
		{
			$this->add($newObject,false);
			$this->remove($current);
		}
	}

	/**
	* returns true if $object is in this store. False if not
     * @param Address|AddressGroup $object
	* @return bool
	*/
	public function inStore($object)
	{
		if( is_null($object) )
			derr('a NULL object? really ?');

		$lower = strtolower($object->name());

		if( isset($this->all[$lower]) )
		{
			if( $this->all[$lower] === $object )
				return true;
		}

		return false;

	}

	
	
	/**
	*
	*
	*/
	public function setCentralStoreRole($is)
	{
		$this->centralStore = $is;
	}
	
	
	/**
	*
	*
	*/
	public function count()
	{
		return count($this->all);
	}
	
	
	
	
	/**
	*
	*
	*/
	public function countAddressGroups()
	{
		if( $this->centralStore)
			return count($this->addrg);

		$count = 0;

		foreach( $this->all as $o)
		{
			if( $o->isGroup() )
				$count++;
		}

		return $count;
	}
	
	
	public function countAddresses()
	{
		if( $this->centralStore)
			return count($this->addr);

		$count = 0;

		foreach( $this->all as $o)
		{
			if( $o->isAddress() )
				$count++;
		}

		return $count;
	}
	
	
	public function countTmpAddresses()
	{
		if( $this->centralStore)
			return count($this->tmpaddr);

		$count = 0;

		foreach( $this->all as $o)
		{
			if( $o->isTmpAddr() )
				$count++;
		}

		return $count;
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
				
				if( isset($curo->owner->addressStore) &&
					!is_null($curo->owner->addressStore)				)
				{
					$this->parentCentralStore = $curo->owner->addressStore;
					//print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
					return;
				}
				$curo = $curo->owner;
			}
		}
		
		//print $this->toString().": no parent store found\n";

	}
	
	/**
	* Should only be called from a CentralStore or give unpredictable results
     * @param string $objectName
	 * @param ReferenceableObject $ref
	 * @param bool $nested
	 * @param string $type
     * @return Address|AddressGroup|null
	*/
	public function find( $objectName , $ref=null, $nested=true, $type = '')
	{
		$f = null;

		$lower = strtolower($objectName);
		
		if( $this->centralStore)
		{
			if( isset($this->all[$lower]) )
			{
				$this->all[$lower]->addReference($ref);
				if( $type == 'tmp' )
				{
					if ( $this->all[$lower]->isTmpAddr() )
						return $this->all[$lower];
					return null;
				}

				return $this->all[$lower];
			}

			if( $nested && isset($this->panoramaShared) )
			{
				$f = $this->panoramaShared->find( $objectName , $ref, false, $type);

				if( !is_null($f) )
					return $f;
			}
			else if( $nested && isset($this->panoramaDG) )
			{
				$f = $this->panoramaDG->find( $objectName , $ref, false, $type);
				if( !is_null($f) )
					return $f;
			}

			if( $nested && $this->parentCentralStore)
			{
				$f = $this->parentCentralStore->find( $objectName , $ref, $nested, $type);
			}

			return $f;
		}

		if( $nested )
			$f = $this->parentCentralStore->find( $objectName , $ref, $nested, $type);
		
		return $f;
	}
	
	public function findOrCreate( $fn , $ref=null, $nested=true)
	{
		if( $this->centralStore)
		{
			$f = $this->find( $fn , $ref, $nested);

			if( $f )
				return $f;

			
			$f = $this->createTmp($fn,$ref);
			
			return $f;
		}
		
		$f = $this->parentCentralStore->findOrCreate( $fn , $ref, $nested);

		return $f;
	}

    /**
     * @param string $name
     * @return Address|null
     */
	public function findTmpAddress($name)
	{
		return $this->find($name , null, false, 'tmp');
	}
	
	public function displayTmpAddresss()
	{
		print "Tmp addresses for ".$this->toString()."\n";
		foreach($this->tmpaddr as $object)
		{
			print " - ".$object->name()."\n";
		}

		print "\n";
	}
	
	
	public function toString_inline()
	{
		$arr = &$this->all;
		$c = count($arr);

		
		if( $c == 0 )
		{
			$ret = '*ANY*';
			return $ret;
		}
		
		$first = true;
		
		$ret = '';
		
		foreach ( $arr as $s )
		{
			if( $first)
			{
				$ret .= $s->name();
			}
			else
				$ret .= ','.$s->name();
			
			
			$first = false;
		}
		
		return $ret;
		
	}

	public function API_add($s, $rewritexml = true)
	{
		$ret = $this->add( $s, $rewritexml);

		if( $ret )
		{
			if( !is_object($s) )
				$s = $this->find( $s );


			$class = get_class($s);
			$con = findConnectorOrDie($this);

			if( $class == 'Address' )
			{
				$xpath = $this->getAddressStoreXPath();
			}
			else if( $class == 'AddressGroup' )
			{
				$xpath = $this->getAddressGroupStoreXPath();
			}
			else
				derr('this class is not supported: '.$class);

			$con->sendSetRequest($xpath, DH::dom_to_xml($s->xmlroot, -1, false) );

		}

		return $ret;
	}
	
	/**
	* @param Address|AddressGroup $s
	* @return bool if object was added. wrong if it was already there or another object with same name.
	*
	*/
	public function add($s, $rewritexml = true)
	{
		//TODO remove strtolower from everywhere
		$this->fasthashcomp = null;


		if( !is_object($s) )
		{
			if( is_string($s) )
			{
				$o = $this->find($s);
				if( is_null($o) )
				{
					derr('could not find object named '.$s);
				}
				return $this->add($o,$rewritexml);
			}
			derr('this is not supported');
		}

		$lower = strtolower($s->name());

		// there is already an object named like that
		if( isset($this->all[$lower]) && $this->all[$lower] !== $s )
		{
			derr('You cannot add object with same name in a store');
		}

		$class = get_class($s);
		
		if( $class == 'Address' )
		{
			if( $s->type() == 'tmp' )
			{
				$this->tmpaddr[$lower] = $s;
			}
			else
			{
				$this->addr[$lower] = $s;
				if( $rewritexml )
                {
                    if( !PH::$UseDomXML )
                        $this->addrroot['children'][] = &$s->xmlroot;
                    else
					{
						$this->addrroot->appendChild($s->xmlroot);
					}
                }
			}
				
			$this->all[$lower] = $s;
			
		}
		elseif ( $class == 'AddressGroup' )
		{
			$this->addrg[$lower] = $s;
			$this->all[$lower] = $s;

			if( $rewritexml )
            {
                if( !PH::$UseDomXML )
                    $this->addrgroot['children'][] = &$s->xmlroot;
                else
                    $this->addrgroot->appendChild($s->xmlroot);
            }
			
		}
		else
			derr('invalid class found');


		$s->owner = $this;


		return true;
	}

	/**
	 * @param Address|AddressGroup $s
	 * @param bool $rewritexml
	 * @param bool $forceAny
	 * @return bool
	 */
	public function API_remove($s, $rewritexml = true, $forceAny = false)
	{
		$xpath = null;

		if( !$s->isTmpAddr() )
			$xpath = $s->getXPath();

		$ret = $this->remove($s, $rewritexml, $forceAny);

		if( $ret && !$s->isTmpAddr())
		{
			$con = findConnectorOrDie($this);
			$con->sendDeleteRequest($xpath);
		}

		return $ret;
	}

    /**
     * @param Address|AddressGroup $s
     * @param bool $rewriteXML
     * @return bool
     */
	public function remove($s, $rewriteXML = true)
	{
		$this->fasthashcomp = null;
		$class = get_class($s);

		$lower = strtolower($s->name());

		
		if( !isset($this->all[$lower]) )
		{
			mdeb('Tried to remove an object that is not part of this store');
			return false;
		}

		unset( $this->all[$lower]);


		if(  $class == 'Address' )
		{
			if( $s->isTmpAddr() )
			{
				unset($this->tmpaddr[$lower]);
			}
			else
			{
				unset($this->addr[$lower]);
			}
		}
		else if( $class == 'AddressGroup' )
		{
			unset($this->addrg[$lower]);
		}
		else
			derr('invalid class found');

		$s->owner = null;

		
		if( $rewriteXML )
		{
			if( $class == "Address" && !$s->isTmpAddr() )
            {
                if(!PH::$UseDomXML)
                    $this->rewriteAddressStoreXML();
                else
                    $this->addrroot->removeChild($s->xmlroot);
            }
            else if( $class == "AddressGroup" )
            {
                if( !PH::$UseDomXML )
                    $this->rewriteAddressGroupStoreXML();
                else
                    $this->addrgroot->removeChild($s->xmlroot);
            }
            else
                derr('unsupported');
        }
		
		return true;
	}


	public function rewriteAddressStoreXML()
	{
		DH::clearDomNodeChilds($this->addrroot);
		foreach( $this->addr as $s )
		{
			$this->addrroot->appendChild($s->xmlroot);
		}
	}

	public function rewriteAddressGroupStoreXML()
	{
		DH::clearDomNodeChilds($this->addrgroot);
		foreach( $this->addrg as $s )
		{
			$this->addrgroot->appendChild($s->xmlroot);
		}
	}

	
	public function newAddress($name , $type, $value, $description = '', $rewriteXML = true)
	{
        $found = $this->find($name,null, true);
        if( $found )
            derr("cannot create Address named '".$name."' as this name is already in use");

		$this->fasthashcomp = null;
		
		$ns = new Address($name,$this, true);
		$ns->setType($type);
		$ns->setValue($value);
		$ns->setDescription($description);

		
		$this->add($ns, $rewriteXML);

		return $ns;
			
	}
	
	
	/**
	* Creates a new Address Group named '$name' . Will exit with error if a group with that 
	* name already exists
	* 
	*
	**/
	public function newAddressGroup($name)
	{

		
		$this->fasthashcomp = null;
		
		$found = $this->find($name,null,true);
		if( $found )
			derr("cannot create AddressGroup named '".$name."' as this name is already in use");
		
		$newGroup = new AddressGroup($name,$this,true);
		$newGroup->setName($name);
		$this->add($newGroup);
		
		return $newGroup;

	}
	
	/**
	* Returns an Array with all AddressGroup in this store.
	 * @return AddressGroup[]
	*
	*/
	public function addressGroups()
	{
		return $this->addrg;
	}
	
	/**
	* Returns an Array with all Address object in this store (which are not 'tmp');
	 * @return Address[]
	*
	*/
	public function addressObjects()
	{
		return $this->addr;
	}
	
	/**
	* Used to create an object that is 'temporary' : means that is not supported (like Regions) 
	* or that is on Panorama. This is a trick to play with objects that don't exist in the conf.
	*
	*/
	function createTmp($name, $ref=null)
	{
		$this->fasthashcomp = null;
		
		$f = new Address($name,$this);
        $f->setValue($name);
		//$f->type = 'tmp';

		$this->add($f);
		$f->addReference($ref);
		
		return $f;
	}
	
	/**
	* Compares address objects with another store to see if they all match each other
	*
	*/
	public function equals( $other )
	{
		
		if( count($this->all) != count($other->all) )
			return false;
		
		
		$indexes = array_keys($this->all);
		
		foreach( $indexes as &$index )
		{
			if( ! isset($other->all[$index]) )
			{
				return false;
			}
			if( $other->all[$index] === $this->all[$index] )
			{
			}
			else
				return false;
		}
		
		
		return true;
	}
	
	/**
	* Same as Equals() but uses faster method for batch use.
	*
	*/
	public function equals_fasterHash( $other )
	{
		if( is_null($this->fasthashcomp) )
		{
			$this->generateFastHashComp();
		}
		if( is_null($other->fasthashcomp) )
		{
			$other->generateFastHashComp();
		}
		
		if( $this->fasthashcomp == $other->fasthashcomp  )
		{
			if( $this->equals($other) )
				return true;
		}
		
		return false;
	}
	
	public function generateFastHashComp($force=false)
	{
		if( !is_null($this->fasthashcomp) && !$force )
			return;
		
		$fasthashcomp = 'AddressStore';
		
		$tmpa = $this->all;
		
		usort($tmpa, "__CmpObjName");
		
		foreach( $tmpa as $o )
		{
			$fasthashcomp .= '.*/'.$o->name();
		}
		
		$this->fasthashcomp = md5($fasthashcomp,true);
		unset($fasthashcomp);
		
	}
	
	public function getFastHashComp()
	{
		$this->generateFastHashComp();
		return $this->fasthashcomp;
	}


	public function hostChanged($h, &$oldName)
	{
		if( ! $this->inStore($h) )
			return false;

		$lower = strtolower($oldName);

		unset($this->all[strtolower($oldName)]);
		$this->all[$lower] = $h;

		$this->fasthashcomp = null;

		$class = get_class($h);

		if( $class == 'Address' )
		{
			unset($this->addr[strtolower($oldName)]);
			$this->addr[$lower] = $h;
		}
		elseif( $class == 'AddressGroup' )
		{
			unset($this->addrg[strtolower($oldName)]);
			$this->addrg[$lower] = $h;
		}
		else
			derr('unsupported class');


		return true;
		
	}


	public function countUnused()
	{
		$count = 0;
		foreach( $this->all as $o )
		{
			if( $o->countReferences() == 0 )
				$count++;
		}

		return $count;
	}

	public function countUnusedAddresses()
	{
		$count = 0;
		foreach( $this->addr as $o )
		{
			if( $o->countReferences() == 0 )
				$count++;
		}

		return $count;
	}

	public function countUnusedAddressGroups()
	{
		$count = 0;
		foreach( $this->addrg as $o )
		{
			if( $o->countReferences() == 0 )
				$count++;
		}

		return $count;
	}


	
}



trait centralAddressStore
{
    /**
     * @var AddressStore|null
     */
	public $addressStore=null;
	
	public function addressStore()
	{
		return $this->addressStore;
	}
}


/**
 * Class centralAddressStoreUser
 * @property VirtualSystem|DeviceGroup|PANConf|PanoramaConf $owner
 */
trait centralAddressStoreUser
{
    /**
     * @var AddressStore|null
     */
	protected $parentAddressStore=null;
	
	public function findParentAddressStore()
	{
		$this->parentAddressStore = null;
		
		if( $this->owner )
		{
			$currentOwner = $this;
			while( isset($currentOwner->owner) && !is_null($currentOwner->owner) )
			{
				
				if( isset($currentOwner->owner->addressStore) &&
					!is_null($currentOwner->owner->addressStore)				)
				{
					$this->parentAddressStore = $currentOwner->owner->addressStore;
					//print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
					return;
				}
				$currentOwner = $currentOwner->owner;
			}
		}
		//die($this->toString()." : not found parent central store: \n");
					
	}
	

}


