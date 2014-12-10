<?php

class Zone
{

	use ReferencableObject;
	use PathableName;

    /**
     * @var null|ZoneStore
     */
    public $owner = null;
	
	private $isTmp = true;

    /**
     * @var null|string[]|DOMNode
     */
    public $xmlroot = null;

    /**
     * @param string $name
     * @param ZoneStore|null $owner
     */
 	public function Zone($name, $owner)
 	{
 		$this->owner = $owner;
		$this->name = $name;
 	}

    /**
     * @param string $newName
     */
 	public function setName($newName)
 	{
        $ret = $this->setRefName($newName);

        if( $this->xmlroot === null )
            return $ret;

        if( PH::$UseDomXML === TRUE )
            $this->xmlroot->getAttributeNode('name')->nodeValue = $newName;
        else
            $this->xmlroot['attributes']['name'] = $newName;

        return $ret;
    }

    public function isTmp()
    {
        return $this->isTmp;
    }

    public function load_from_xml(&$xmlArray)
    {
        $this->xmlroot = &$xmlArray;
        $this->isTmp = false;

        if( !isset($xmlArray['attributes']['name']) )
            derr('Zone name not found');

        $this->name = $this->xmlroot['attributes']['name'];

        if( strlen($this->name) < 1  )
            derr("Zone name '".$this->name."' is not valid");
    }

    public function load_from_domxml(DOMNode $xml)
    {
        $this->xmlroot = $xml;
        $this->isTmp = false;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("zone name not found\n", $xml);

        if( strlen($this->name) < 1  )
            derr("Zone name '".$this->name."' is not valid", $xml);

    }

    public function API_setName($newname)
    {
        if(! $this->isTmp() )
        {
            $c = findConnectorOrDie($this);

            $path = $this->getXPath();

            $c->sendRenameRequest($path, $newname);
        }
        else
        {
            mwarning('this is a temporary object, cannot be renamed from API');
        }

        $this->setName($newname);
    }

    public function &getXPath()
    {
        if( $this->isTmp() )
            derr('no xpath on temporary objects');

        $str = $this->owner->getXPath()."/entry[@name='".$this->name."']";

        return $str;
    }
 	
	
}



