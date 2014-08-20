<?xml version="1.0" standalone="yes"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:junos="http://xml.juniper.net/junos/*/junos"
    xmlns:xnm="http://xml.juniper.net/xnm/1.1/xnm"
    xmlns:jcs="http://xml.juniper.net/junos/commit-scripts/1.0">
    <xsl:import href="../import/junos.xsl"/>

    <!-- main() -->

    <xsl:template match="/">
	<op-script-results>
	    <xsl:call-template name="update-policy"/>
	</op-script-results>
    </xsl:template>

    <xsl:template name="update-policy">

	<!-- Lock the configuration -->

	<xsl:variable name="lock-result">
	    <xsl:call-template name="lock-config"/>
	</xsl:variable>

	<xsl:choose>

	    <xsl:when test="$lock-result='true'">

		<!-- Do the syntax sanity check before changing it -->

		<xsl:variable name="check-result">
		    <xsl:call-template name="check-config"/>
		</xsl:variable>

		<xsl:choose>

		    <xsl:when test="$check-result='true'">

			<!-- Make configuration changes -->

			<xsl:variable name="policy">
			    <load-configuration action="replace">
				<configuration>
				    <policy-options>
