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

class RuleStore
{
	use PathableName;

	/**
	 * @var Rule[]|SecurityRule[]|NatRule[]|DecryptionRule[]
	 */
	protected $o = Array();
    /**
     * @var VirtualSystem|DeviceGroup|PanoramaConf|PANConf
     */
	public $owner = null;
	public $name = 'temporaryname';
	/**
	 * @var string[]|DOMElement
	 */
	public $xmlroot;
	protected $type = '**needsomethinghere**';
	protected $fastMemToIndex=null;
	protected $fastNameToIndex=null;

	protected $isStore = false;

    protected $isPreRulebase = null;


    static private $storeNameByType = Array(

        'SecurityRule' => Array( 'name' => 'Security', 'varName' => 'SecurityRules', 'xpathRoot' => 'security' ),
        'NatRule' => Array( 'name' => 'NAT', 'varName' => 'NatRules', 'xpathRoot' => 'nat' ),
        'DecryptionRule' => Array( 'name' => 'Decryption', 'varName' => 'DecryptRules', 'xpathRoot' => 'decryption' )

    );
 
	public function RuleStore($owner=null)
	{
		$this->owner = $owner;
	}
	
	/**
	* For developper use only
	*
	*/
	public function setStoreRole($isStore , $type, $preRulebase = null)
	{
		$this->setType($type, $preRulebase);
		$this->isStore = $isStore;
	}
	
	/**
	* For developper use only
     * @param string
	* @param bool|null
	*/
	protected function setType($type, $preRulebase = null)
	{
		$allowedTypes = array_keys(self::$storeNameByType);
		if( ! in_array($type, $allowedTypes) )
			derr("Error : type '$type' is not a valid one");
		$this->type = $type;

        $this->isPreRulebase = $preRulebase;

        if( $preRulebase === null )
        {
            $this->name = self::$storeNameByType[$this->type]['name'];
        }
        else if( $preRulebase )
        {
            $this->name = 'Pre-'.self::$storeNameByType[$this->type]['name'];
        }
        else
            $this->name = 'Post-'.self::$storeNameByType[$this->type]['name'];
	}


	
	/**
	* Counts how many NAT rules in this Store are DIPP. If $countDisabledRules=true then it also count disabled rules
	* @param bool $countDisabledRules
     * @return bool
	*/
	public function countDyn_IP_and_Port_SNat( $countDisabledRules = false)
	{
		if( $this->type != 'NatRule' )
		{
			derr('this function cannot be called on type = "'.$this->type.'"');
		}
		
		$count = 0;
		
		foreach($this->o as $rule)
		{
			if( $rule->SNat_Type() == 'dynamic-ip-and-port' )
			{
				if( $rule->isDisabled() && $countDisabledRules ||  !$rule->isDisabled() )
				{
					$count++;
				}
			}
		}
		
		return $count;
	}



	/**
	 * For developper use only
	 * @param DOMElement $xml
	 */
	public function load_from_domxml($xml)
	{
		global $PANC_DEBUG;

		if( ! $this->isStore )
		{
			derr($this->toString()." : Error, this function '".__FUNCTION__."' should never called from non CentralStore object\n");
		}
		
		$this->xmlroot = $xml;		
		$count = 0;
		
		foreach( $xml->childNodes as $node )
		{
			if( $node->nodeType != 1 ) continue;
			$count++;
			if( $PANC_DEBUG && $count%1000 == 0 )
				print "Parsed $count rules so far\n";
			$nr = new $this->type($this);
			$nr->load_from_domxml($node);
			$this->o[] = $nr;
		}
		
		$this->regen_Indexes();
	}


	/**
	 * @param Rule $rule
	 * @return bool
	 */
	public function addRule($rule)
	{
		
		if( !is_object($rule) )
			derr('this function only accepts Rule class objects');
		
		
		$ser = spl_object_hash($rule);
		
		if( !isset($this->fastMemToIndex[$ser] ) )
		{
            $rule->owner = $this;
			
			$this->o[] = $rule;
			$index = lastIndex($this->o);
			$this->fastMemToIndex[$ser] = $index;
			$this->fastNameToIndex[$rule->name()] = $index;
			if($this->isStore )
			{
				$this->xmlroot->appendChild($rule->xmlroot);
			}
			
			return true;
			
		}
		else
			derr('You cannot add a Rule that is already here :)');
			
		return false;

	}


	/**
	 * @param Rule $rule
	 * @return bool
	 */
	public function API_addRule( $rule )
	{
		if( ! $this->addRule($rule) )
            return false;

		$xpath = $this->getXPath();
		$con = findConnectorOrDie($this);

		$con->sendSetRequest($xpath, DH::dom_to_xml($rule->xmlroot, -1, false) );

        return true;
	}

	/**
	 * @param Rule $rule
	 * @return bool
	 */
	public function moveRuleToPostRulebase( $rule )
	{

		if( $this->isPreRulebase !== true )
			derr('tried to move a rule that is not in a Pre-SecRules base');

		if( !$this->remove($rule) )
			return false;

        $this->getOppositeStore()->addRule($rule);

		return true;
	}

	/**
	 * @param Rule $rule
	 * @return bool
	 */
	public function API_moveRuleToPostRulebase( $rule )
	{
        if( $this->isPreRulebase !== true )
            derr('tried to move a rule that is not in a Pre-SecRules base');

        if( !$this->API_remove($rule) )
            return false;

        $this->getOppositeStore()->API_addRule($rule);

        return true;
	}


	/**
	 * @param Rule $rule
	 * @return bool
	 */
	public function moveRuleToPreRulebase( $rule )
	{
        if( $this->isPreRulebase !== false )
            derr('tried to move a rule that is not in a Pre-SecRules base');

        if( !$this->remove($rule) )
            return false;

        $this->getOppositeStore()->addRule($rule);

        return true;
	}


	/**
	 * @param Rule $rule
	 * @return bool
	 */
	public function API_moveRuleToPreRulebase( $rule )
	{
        if( $this->isPreRulebase !== false )
            derr('tried to move a rule that is not in a Pre-SecRules base');

        if( !$this->API_remove($rule) )
            return false;

        $this->getOppositeStore()->API_addRule($rule);

        return true;
	}


	
	/**
	* Check if this name is available (for new rule for example)
	* @param string $name
     * @param bool $nested
     * @return bool
	*/
	public function isRuleNameAvailable($name, $nested=true)
	{
		if( isset($this->fastNameToIndex[$name]) )
		{
			return false;
		}

		if( !$nested )
			return true;

		$ownerC = get_class($this->owner);

		if( $ownerC == 'VirtualSystem' )
		{
			//return $this->owner->owner->
		}
        else if( $ownerC == 'PanoramaConf' )
        {
            if( !$this->getOppositeStore()->isRuleNameAvailable($name, false) )
                return false;
        }
		else if( $ownerC == 'DeviceGroup' )
		{
            $oppositeStore = $this->getOppositeStore();

			if( !$oppositeStore->isRuleNameAvailable($name, false) )
				return false;

            $varName = $oppositeStore->getStoreVarName();

			if( !$this->owner->owner->$varName->isRuleNameAvailable($name, false) )
				return false;

            $varName = $this->getStoreVarName();

			if( !$this->owner->owner->$varName->isRuleNameAvailable($name, false) )
				return false;
		}
		else
			derr('unsupported');
		
		return true;
	}

    /**
     * @return RuleStore
     */
    function getOppositeStore()
    {
        $varName = self::$storeNameByType[$this->type]['varName'];
        if( $this->isPreRulebase() )
            $varName = 'post'.$varName;
        else
            $varName = 'pre'.$varName;

        return $this->owner->$varName;
    }

	/**
	 * @return string
	 */
    function &getStoreVarName()
    {
        $varName = self::$storeNameByType[$this->type]['varName'];
        if( !$this->isPreRulebase() )
            $varName = 'post'.$varName;
        else
            $varName = 'pre'.$varName;

        return $varName;
    }


	/**
	 * @param string $base
	 * @param string $suffix
	 * @return string
	 */
	public function findAvailableName($base, $suffix)
	{
		$maxl = 31;
		$basel = strlen($base);
		$suffixl = strlen($suffix);
		$inc = 1;
		$basePlusSuffixL = $basel + $suffixl;

		while(true)
		{

			$incl = strlen(strval($inc));

			if( $basePlusSuffixL + $incl > $maxl )
			{
				$newname = substr($base,0, $basel-$suffixl-$incl).$suffix.$inc;
			}
			else
				$newname = $base.$suffix.$inc;

			if( $this->isRuleNameAvailable($newname) )
				return $newname;

			$inc++;
		}
	}
	
	/**
	* Only used internally when a rule is renamed to check for it unicity and accurate indexing
	* @param SecurityRule|NatRule $rule
     * @param string $oldName
	*/
	public function ruleWasRenamed($rule, $oldName)
	{
        if( $rule === null )
            derr("Rule cannot be null");
		if( !$this->isRuleNameAvailable($rule->name()) )
			derr("Rule '".$rule->name()."' previously named '".$oldName."' cannot be renamed because this name is already in use");
		
		$this->fastNameToIndex[$rule->name()] = $this->fastNameToIndex[$oldName];
		unset($this->fastNameToIndex[$oldName]);
	}


    /**
     * @param SecurityRule|NatRule $rule
     * @param string $newName
     * @return SecurityRule|NatRule
     */
	public function cloneRule($rule, $newName)
	{
		if( !$this->isRuleNameAvailable($newName) )
			derr('this rule name is not available: '.$newName);

		$xml = $rule->xmlroot->cloneNode(true);

		$nr = new $this->type($this);

		$nr->load_from_domxml($xml);
		$this->addRule($nr);

		$nr->setName($newName);


		return $nr;
	}

	/**
	 * @param Rule $rule
	 * @param string $newName
	 * @return NatRule|SecurityRule
	 */
	public function API_cloneRule($rule, $newName)
	{
		$nr = $this->cloneRule($rule, $newName);

		$con = findConnectorOrDie($this);

		$xpath = $this->getXPath();
		$element = array_to_xml($nr->xmlroot, -1, false);

		$con->sendSetRequest($xpath, $element);

		return $nr;
	}


	/**
	 * this function will move $ruleToBeMoved after $ruleRef.
	 * @param Rule $ruleToBeMoved
	 * @param Rule $ruleRef
	 * @param bool $rewritexml
	 */
	public function moveRuleAfter( $ruleToBeMoved , $ruleRef, $rewritexml=true )
	{
		if( is_string($ruleToBeMoved) )
		{
			if( !isset($this->fastNameToIndex[$ruleToBeMoved]) )
				derr('Cannot move a rule that is not part of this Store');
			 $rtbv = $this->o[$this->fastNameToIndex[$ruleToBeMoved]];
			 $rtbvs = spl_object_hash($rtbv);
		}
		else
		{
			$rtbvs = spl_object_hash($ruleToBeMoved);
			if( !isset($this->fastMemToIndex[$rtbvs]) )
				derr('Cannot move a rule that is not part of this Store');
				
			$rtbv = $ruleToBeMoved;
		}
		
		if( is_string($ruleRef) )
		{
			if( !isset($this->fastNameToIndex[$ruleRef]) )
				derr('Cannot move after a rule that is not part of this Store');
			
			 $rtref = $this->o[$this->fastNameToIndex[$ruleRef]];
			 $rtrefs = spl_object_hash( $rtref );
		}
		else
		{
			$rtrefs = spl_object_hash($ruleRef);
			if( !isset($this->fastMemToIndex[$rtrefs]) )
				derr('Cannot move after a rule that is not part of this Store');
				
			$rtref = $ruleRef;
		}
		
		$i = 0;
		$newarr = Array();
		
		
		foreach($this->o as $rule)
		{
			if( $rule === $rtbv )
			{
				continue;
			}
			
			$newarr[$i] = $rule;
			
			$i++;
			
			if( $rule === $rtref )
			{
				$newarr[$i] = $rtbv;
				$i++;
			}
		}
		
		$this->o = &$newarr;
		
		$this->regen_Indexes();
		
		if( $rewritexml )
			$this->rewriteXML();
	}

	/**
	 * @param Rule $ruleToBeMoved
	 * @param Rule $ruleRef
	 * @param bool $rewritexml
	 */
	public function API_moveRuleAfter( $ruleToBeMoved , $ruleRef, $rewritexml=true )
	{
		$this->moveRuleAfter($ruleToBeMoved , $ruleRef, $rewritexml);

		$xpath = $ruleToBeMoved->getXPath();
		$con = findConnectorOrDie($this);

		$url = 'type=config&action=move&xpath='.$xpath.'&where=after&dst='.$ruleRef->name();
		$con->sendRequest($url);

	}


	/**
	 * this function will move $ruleToBeMoved before $ruleRef.
	 * @param Rule $ruleToBeMoved
	 * @param Rule $ruleRef
	 * @param bool $rewritexml
	 */
	public function moveRuleBefore( $ruleToBeMoved , $ruleRef, $rewritexml=true )
	{
		if( is_string($ruleToBeMoved) )
		{
			if( !isset($this->fastNameToIndex[$ruleToBeMoved]) )
				derr('Cannot move a rule that is not part of this Store');
			 $rtbv = $this->o[$this->fastNameToIndex[$ruleToBeMoved]];
			 $rtbvs = spl_object_hash($rtbv);
		}
		else
		{
			$rtbvs = spl_object_hash($ruleToBeMoved);
			if( !isset($this->fastMemToIndex[$rtbvs]) )
				derr('Cannot move a rule that is not part of this Store');
				
			$rtbv = $ruleToBeMoved;
		}
		
		if( is_string($ruleRef) )
		{
			if( !isset($this->fastNameToIndex[$ruleRef]) )
				derr('Cannot move after a rule that is not part of this Store');
			
			 $rtref = $this->o[$this->fastNameToIndex[$ruleRef]];
			 $rtrefs = spl_object_hash( $rtref );
		}
		else
		{
			$rtrefs = spl_object_hash($ruleRef);
			if( !isset($this->fastMemToIndex[$rtrefs]) )
				derr('Cannot move after a rule that is not part of this Store');
				
			$rtref = $ruleRef;
		}
		
		$i = 0;
		$newarr = Array();
		
		
		foreach($this->o as $rule)
		{
			if( $rule === $rtbv )
			{
				continue;
			}
			
			
			if( $rule === $rtref )
			{
				$newarr[$i] = $rtbv;
				$i++;
			}
			
			$newarr[$i] = $rule;
			
			$i++;
			
		}
		
		$this->o = &$newarr;
		
		$this->regen_Indexes();
		
		if( $rewritexml )
			$this->rewriteXML();
	}

	/**
	 * @param Rule $ruleToBeMoved
	 * @param Rule $ruleRef
	 * @param bool $rewritexml
	 */
	public function API_moveRuleBefore( $ruleToBeMoved , $ruleRef, $rewritexml=true )
	{
		$this->moveRuleBefore($ruleToBeMoved , $ruleRef, $rewritexml);

		$xpath = $ruleToBeMoved->getXPath();
		$con = findConnectorOrDie($this);

		$url = 'type=config&action=move&xpath='.$xpath.'&where=before&dst='.$ruleRef->name();
		$con->sendRequest($url);
	}
	
	
	/**
	* Returns an Array with all Rules inside this store
	* @return SecurityRule[]|NatRule[]
	*/
	public function rules()
	{
		return $this->o;
	}
	
	/**
	* Counts the number of rules in this store
	*
	*/
	public function count()
	{
		return count($this->o);
	}
	
	
	/**
	* Displays all rules inside this store in a more less readable format :)
	*
	*/
	public function display()
	{
		foreach($this->o as $r )
		{
			$r->display();
		}
	}
	
	/**
	* Look for a rule named $name. Return NULL if not found
     * @param string $name
	* @return Rule|SecurityRule|NatRule|DecryptionRule
	*/
	public function find($name)
	{
		if( !is_string($name) )
			derr("String was expected for rule name");
		
		if( isset( $this->fastNameToIndex[$name]) )
			return $this->o[$this->fastNameToIndex[$name]];
		
		return null;
	}
	
	/**
	* Creates a new SecurityRule in this store. It will be placed at the end of the list.
	*
	*/
	public function newSecurityRule($name)
	{
		$rule = new SecurityRule($this,true);
		$this->addRule($rule);
		$rule->setName($name);		
		
		return $rule;
			
	}

	public function newNatRule($name)
	{
		$rule = new NatRule($this,true);
		$this->addRule($rule);
		$rule->setName($name);		
		
		return $rule;
			
	}
	
	
	/**
	* Removes a rule from this store (must be passed an object, not string/name). Returns TRUE if found.
	*
	*/
	public function remove( $rule, $rewritexml=true, $deleteForever = false )
	{

		$found = false;
		$ser = spl_object_hash($rule);
		
		if( isset($this->fastMemToIndex[$ser] ) )
		{
			$found = true;
			unset($this->fastNameToIndex[$rule->name()]);
			unset($this->o[$this->fastMemToIndex[$ser]]);
			unset($this->fastMemToIndex[$ser]);
			$this->xmlroot->removeChild($rule->xmlroot);
			$rule->owner = null;

			if( $deleteForever )
			{
				$rule->cleanForDestruction();
			}
		}
		
		return $found;
	}


	/**
	* Removes a rule from this store (must be passed an object, not string/name). Returns TRUE if found.
	*
	*/
	public function API_remove( $rule, $rewritexml=true )
	{
		$xpath = $rule->getXPath();
		$ret = $this->remove($rule, $rewritexml);

		if( $ret )
		{
			$con = findConnectorOrDie($this);

			$con->sendDeleteRequest($xpath);
		}

		return $ret;
	}
	
	
	/**
	* Rewrite XML for this object, useful after a batch editing to save computing time.
	* You should not need to call it by yourself in normal situations
	*
	*/
	public function rewriteXML()
	{
		DH::clearDomNodeChilds($this->xmlroot);
		foreach( $this->o as $rule )
		{
			$this->xmlroot->appendChild($rule->xmlroot);
		}
	}
	
	protected function regen_Indexes()
	{

		$this->fastMemToIndex = Array();
		$this->fastNameToIndex = Array();
		
		foreach($this->o as $i=>$rule)
		{
			$this->fastMemToIndex[spl_object_hash($rule)] = $i ;
			$this->fastNameToIndex[$rule->name()] = $i ;
		}
	}
	
	public function name()
	{
		return $this->name;
	}

	public function &getXPath()
	{

			$class = get_class($this->owner);

			$str = '';

			if( $class == 'VirtualSystem' )
			{
				$str = $this->owner->getXPath().'/rulebase';
			}
			else if ($class == 'DeviceGroup' )
			{
				if( $this->isPreRulebase === true )
					$str = $this->owner->getXPath().'/pre-rulebase';
				else if( $this->isPreRulebase === false )
					$str = $this->owner->getXPath().'/post-rulebase';
				else
					derr('unsupported mode');
			}
			else if ($class == 'PANConf' )
			{
				$str = "/config/shared/rulebase";
                derr('unsupported');
			}
			else if ($class == 'PanoramaConf' )
			{
                if( $this->isPreRulebase === true )
					$str = "/config/shared/pre-rulebase";
                else if( $this->isPreRulebase === false )
					$str = "/config/shared/post-rulebase";
				else derr('unsupported mode');
			}
			else
				derr('unsupported mode');


            $str .= '/'.self::$storeNameByType[$this->type]['xpathRoot'].'/rules';



			return $str;
	}

    function isPreRulebase()
    {
        if( $this->isPreRulebase === null )
            return false;

        return $this->isPreRulebase;
    }

    function isPostRulebase()
    {
        if( $this->isPreRulebase === null )
            return false;

        return !$this->isPreRulebase;
    }
 
	
}


