<?php

/*
 * Copyright (c) 2014-2017 Christophe Painchaud <shellescape _AT_ gmail.com>
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
trait ReferencableObject
{

	protected $name;
	public $refrules = Array();
	protected $refcomphash = null;

    /**
     * @param string $newName
     * @param bool $skip_name_unicity_check
     * @throws Exception
     * @return bool
     */
	protected function setRefName($newName, $skip_name_unicity_check = false)
	{
        if( !is_string($newName) )
            derr('$newName must be a string');

        if( $this->name == $newName )
            return false;

		$oldName = $this->name;
		$this->name = $newName;
		
		$this->broadcastMyNameChange($oldName);

        return true;
	}
	
	public function addReference($ref)
	{
		if( $ref === null )
			return;

		$serial = spl_object_hash($ref);

		if( isset($this->refrules[$serial]) )
			return;

		$this->refrules[$serial] = $ref;
		$this->refcomphash = null;
	}
	
	public function removeReference($ref)
	{
		if( $ref === null )
			return;

		$serial = spl_object_hash($ref);

		if( isset($this->refrules[$serial]) )
		{
			unset($this->refrules[$serial]);
			$this->refcomphash = null;
			return;
		}

		mwarning('tried to unreference an object that is not referenced:'.$this->toString().'  against  '.$ref->toString());
	}
	
	public function broadcastMyNameChange($oldname)
	{
		
		foreach( $this->refrules as $ref )
		{
			$ref->referencedObjectRenamed($this,$oldname);
		}
		
		if( $this->owner !== null )
		{
			$this->owner->referencedObjectRenamed($this,$oldname);
		}
	}
	
	public function replaceMeGlobally($newobject)
	{
		foreach( $this->refrules as $o )
		{
			$o->replaceReferencedObject($this, $newobject);
		}
	}

    /**
     * @param $objectToAdd Service|ServiceGroup
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function addObjectWhereIamUsed($objectToAdd, $displayOutput = false, $outputPadding = '', $skipIfConflict = false)
    {
        derr('not implemented yet');
    }

    /**
     * @param $objectToAdd Service|ServiceGroup
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function API_addObjectWhereIamUsed($objectToAdd, $displayOutput = false, $outputPadding = '', $skipIfConflict = false)
    {
        derr('not implemented yet');
    }
	
	
	public function countReferences()
	{
		return count($this->refrules);
	}

	
	public function display_references($indent=0)
	{
		$strpad = str_pad('',$indent);
		print $strpad."* Displaying referencers for ".$this->toString()."\n";
		foreach( $this->refrules as $o )
		{
			print $strpad.'  - '.$o->toString()."\n";
		}
	}

	/**
	 * @return SecurityRule[]
	 */
	public function findAssociatedSecurityRules()
	{
		return $this->findAssociatedRule_byType('SecurityRule');
	}

	/**
	 * @param string $type
	 * @return Rule[]
	 */
	public function findAssociatedRule_byType($type)
	{
		$ret = Array();

		foreach( $this->refrules as $cur)
		{
			if( isset($cur->owner) && $cur->owner !== null )
			{
				$class = get_class($cur->owner);
				//print $cur->owner->toString()."\n";
				if( $class == $type )
				{
					if( !in_array($cur->owner, $ret, TRUE) )
					{
						$ret[] = $cur->owner;
					}
				}
				
			}
		}
		
		return $ret;
	}
	
	
	public function generateRefHashComp($force=false)
	{
		if( $this->refcomphash !== null && !$force )
			return;
		
		$fasthashcomp = 'ReferenceableObject';
		
		$tmpa = $this->refrules;
		
		usort($tmpa, "__CmpObjMemID");
		
		foreach( $tmpa as $o )
		{
			$fasthashcomp .= '.*/'.spl_object_hash($o);
		}
		
		$this->refcomphash = md5($fasthashcomp,true);
		
	}
	
	public function getRefHashComp()
	{
		$this->generateRefHashComp();
		return $this->refcomphash;
	}

    public function getReferences()
    {
        return $this->refrules;
    }

    public function getReferencesLocation()
    {
        $location_array = array();
        foreach( $this->refrules as $cur )
        {
            if( isset($cur->owner->owner->owner) && $cur->owner->owner->owner !== null )
                $location_array[$cur->owner->owner->owner->name()] = $cur->owner->owner->owner->name();
        }

        return $location_array;
    }

    public function getReferencesStore()
    {
        $store_array = array();
        foreach( $this->refrules as $cur )
        {
            if( isset($cur->owner->owner) && $cur->owner->owner !== null )
            {
                $class = get_class($cur->owner->owner);
                $class = strtolower($class);
                $store_array[$class] = $class;
            }

        }
        return $store_array;
    }

    /**
     * @param string $value
     */
    public function ReferencesStoreValidation( $value )
    {
        $store_array = array( );
        $store_array['addressstore'] = false;
        $store_array['servicestore'] = false;
        $store_array['rulestore'] = false;

        if( !array_key_exists( $value, $store_array ) )
        {
            $store_string = "";
            $first = true;
            foreach(array_keys($store_array) as $storeName)
            {
                if( $first )
                {
                    $store_string .= "'".$storeName."'";
                    $first = false;
                }
                else
                    $store_string .= ", '".$storeName."'";
            }

            derr( "this is not a store name: '".$value."' | possible names: ".$store_string."\n" );
        }
    }

    public function getReferencesType()
    {
        $type_array = array();
        foreach( $this->refrules as $cur )
        {
            if( isset($cur->owner) && $cur->owner !== null )
            {
                $class = get_class($cur->owner);
                $class = strtolower($class);
                $type_array[$class] = $class;
            }

        }
        return $type_array;
    }

    /**
     * @param string $value
     */
    public function ReferencesTypeValidation( $value )
    {
        $type_array = array( );
        $type_array['address'] = false;
        $type_array['addressgroup'] = false;
        $type_array['service'] = false;
        $type_array['servicegroup'] = false;
        $type_array['securityrule'] = false;
        $type_array['natrule'] = false;
        $type_array['natrule'] = false;
        $type_array['decryptionrule'] = false;
        $type_array['appoverriderule'] = false;
        $type_array['captiveportalrule'] = false;
        $type_array['authenticationrule'] = false;
        $type_array['pbfrule'] = false;
        $type_array['qosrule'] = false;
        $type_array['dosrule'] = false;

        if( !array_key_exists( $value, $type_array ) )
        {
            $type_string = "";
            $first = true;
            foreach(array_keys($type_array) as $typeName)
            {
                if( $first )
                {
                    $type_string .= "'".$typeName."'";
                    $first = false;
                }
                else
                    $type_string .= ", '".$typeName."'";
            }

            derr( "this is not a type name: '".$value."' | possible names: ".$type_string."\n" );
        }
    }

    /**
     * @param string $className
     * @return array
     */
    public function & findReferencesWithClass($className)
    {
        $ret = Array();

        foreach($this->refrules as $reference)
        {
            if( get_class($reference) == $className )
                $ret[] = $reference;
        }

        return $ret;
    }
	
	
	public function name()
	{
		return $this->name;
	}
	
}
