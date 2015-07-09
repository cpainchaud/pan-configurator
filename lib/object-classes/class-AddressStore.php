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
     * @param VirtualSystem|DeviceGroup|PanoramaConf|PANConf|null $owner
     */
	public function AddressStore($owner)
	{
		$this->owner = $owner;

        if( isset($owner->parentDeviceGroup) && $owner->parentDeviceGroup !== null )
            $this->parentCentralStore = $owner->parentDeviceGroup->addressStore;
		else
            $this->findParentCentralStore();

		$this->addr = Array();
		$this->addrg = Array();
		$this->tmpaddr = Array();
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
		$path = $this->getBaseXPath().'/address';
		return $path;
	}

	public function &getAddressGroupStoreXPath()
	{
		$path = $this->getBaseXPath().'/address-group';
		return $path;
	}
	
	
	
	/**
	* For developper use only
	*
	*/
	public function load_addresses_from_domxml($xml)
	{
        $this->addrroot = $xml;
		
		foreach( $this->addrroot->childNodes as $node )
		{
			if( $node->nodeType != 1 ) continue;

			$ns = new Address('',$this);
			$ns->load_from_domxml($node);
			//print $this->toString()." : new service '".$ns->name()."' created\n";

			$objectName = $ns->name();

			$this->addr[$objectName] = $ns;
			$this->all[$objectName] = $ns;
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

			$objectName = $ns->name();

			$this->addrg[$objectName] = $ns;
			$this->all[$objectName] = $ns;
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

		$objectName = $object->name();

		if( isset($this->all[$objectName]) )
		{
			if( $this->all[$objectName] === $object )
				return true;
		}

		return false;

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
		return count($this->addrg);
	}
	
	
	public function countAddresses()
	{
		return count($this->addr);
	}
	
	
	public function countTmpAddresses()
	{
		return count($this->tmpaddr);
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

        if( isset($this->all[$objectName]) )
        {
            $this->all[$objectName]->addReference($ref);
            if( $type == 'tmp' )
            {
                if ( $this->all[$objectName]->isTmpAddr() )
                    return $this->all[$objectName];
                return null;
            }

            return $this->all[$objectName];
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
	
	public function findOrCreate( $fn , $ref=null, $nested=true)
	{
		$f = $this->find( $fn , $ref, $nested);

		if( $f !== null )
			return $f;

		$f = $this->createTmp($fn,$ref);
			
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

    /**
     * @param $s Address|AddressGroup
     * @return bool
     */
	public function API_add($s)
	{
		$ret = $this->add($s);

		if( $ret )
		{
			$con = findConnectorOrDie($this);
			$xpath = $s->getXPath();
			$con->sendSetRequest($xpath, DH::domlist_to_xml($s->xmlroot->childNodes, -1, false) );
		}

		return $ret;
	}

    /**
     * @param Address|AddressGroup $s
     * @return bool if object was added. wrong if it was already there or another object with same name.
     *
     * @throws Exception
     */
	public function add($s)
	{
		$objectName = $s->name();

		// there is already an object named like that
		if( isset($this->all[$objectName]) && $this->all[$objectName] !== $s )
		{
			derr('You cannot add object with same name in a store');
		}

		$class = get_class($s);
		
		if( $class == 'Address' )
		{
			if( $s->type() == 'tmp' )
			{
				$this->tmpaddr[$objectName] = $s;
			}
			else
			{
				$this->addr[$objectName] = $s;
				$this->addrroot->appendChild($s->xmlroot);
			}
				
			$this->all[$objectName] = $s;
		}
		elseif ( $class == 'AddressGroup' )
		{
			$this->addrg[$objectName] = $s;
			$this->all[$objectName] = $s;

            $this->addrgroot->appendChild($s->xmlroot);
			
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
		$class = get_class($s);

		$objectName = $s->name();

		
		if( !isset($this->all[$objectName]) )
		{
			mdeb('Tried to remove an object that is not part of this store');
			return false;
		}

		unset( $this->all[$objectName]);


		if(  $class == 'Address' )
		{
			if( $s->isTmpAddr() )
			{
				unset($this->tmpaddr[$objectName]);
			}
			else
			{
				unset($this->addr[$objectName]);
			}
		}
		else if( $class == 'AddressGroup' )
		{
			unset($this->addrg[$objectName]);
		}
		else
			derr('invalid class found');

		$s->owner = null;

		
		if( $rewriteXML && !$s->isTmpAddr() )
		{
			if( $class == "Address" )
            {
                $this->addrroot->removeChild($s->xmlroot);
            }
            else if( $class == "AddressGroup" )
            {
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


    /**
     * @param $name string
     * @param $type string
     * @param $value string
     * @param string $description
     * @return Address
     * @throws Exception
     */
	public function newAddress($name , $type, $value, $description = '')
	{
        $found = $this->find($name,null, true);
        if( $found !== null )
            derr("cannot create Address named '".$name."' as this name is already in use");
		
		$newObject = new Address($name,$this, true);
		$newObject->setType($type);
		$newObject->setValue($value);
		$newObject->setDescription($description);

		$this->add($newObject);

		return $newObject;
	}

    /**
     * @param $name string
     * @param $type string
     * @param $value string
     * @param string $description
     * @return Address
     * @throws Exception
     */
    public function API_newAddress($name , $type, $value, $description = '')
    {
        $newObject = $this->newAddress($name, $type, $value, $description);

        $con = findConnectorOrDie($this);
        $xpath = $newObject->getXPath();
        $con->sendSetRequest($xpath, $newObject, true );

        return $newObject;
    }
	
	
	/**
	* Creates a new Address Group named '$name' . Will exit with error if a group with that 
	* name already exists
	* @param $name string
	* @return AddressGroup
	**/
	public function newAddressGroup($name)
	{
		$found = $this->find($name,null,true);
		if( $found !== null )
			derr("cannot create AddressGroup named '".$name."' as this name is already in use");
		
		$newGroup = new AddressGroup($name,$this,true);
		$newGroup->setName($name);
		$this->add($newGroup);
		
		return $newGroup;

	}

    /**
     * Creates a new Address Group named '$name' . Will exit with error if a group with that
     * name already exists
     * @param $name string
     * @return AddressGroup
     **/
    public function API_newAddressGroup($name)
    {
        $found = $this->find($name,null,true);
        if( $found !== null )
            derr("cannot create AddressGroup named '".$name."' as this name is already in use");

        $newObject = $this->newAddressGroup($name);

        $con = findConnectorOrDie($this);
        $xpath = $newObject->getXPath();
        $con->sendSetRequest($xpath, $newObject, true );

        return $newObject;
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
		$f = new Address($name,$this);
        $f->setValue($name);
		//$f->type = 'tmp';

		$this->add($f);
		$f->addReference($ref);
		
		return $f;
	}


	public function referencedObjectRenamed($h, $oldName)
	{
		if( $this->all[$oldName] !== $h)
        {
            mwarning("Unexpected : object is not part of this library");
            return false;
        }

        $newName = $h->name();

		unset($this->all[$oldName]);
		$this->all[$newName] = $h;

		$class = get_class($h);

		if( $class == 'Address' )
		{
			unset($this->addr[$oldName]);
			$this->addr[$newName] = $h;
		}
		elseif( $class == 'AddressGroup' )
		{
			unset($this->addrg[$oldName]);
			$this->addrg[$newName] = $h;
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


