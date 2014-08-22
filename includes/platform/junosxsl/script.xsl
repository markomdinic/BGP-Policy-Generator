<?xml version="1.0" standalone="yes"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:junos="http://xml.juniper.net/junos/*/junos"
    xmlns:xnm="http://xml.juniper.net/xnm/1.1/xnm"
    xmlns:jcs="http://xml.juniper.net/junos/commit-scripts/1.0"
    xmlns:exsl="http://exslt.org/common"
    xmlns:ext="http://xmlsoft.org/XSLT/namespace">

    <xsl:import href="../import/junos.xsl"/>

    <!-- main() -->

    <xsl:template match="/">
	<op-script-results>
	    <xsl:call-template name="commit-policy"/>
	</op-script-results>
    </xsl:template>

    <!-- Apply policy changes -->

    <xsl:template name="commit-policy">
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
		    <!-- If config syntax checks out, proceed -->
		    <xsl:when test="$check-result='true'">
			<!-- Make policy configuration changes -->
			<xsl:variable name="policy">
			    <load-configuration action="replace">
				<configuration>
				    <policy-options>
					<!-- ##### POLICY PLACEHOLDER ###### DO NOT CHANGE ##### -->
				    </policy-options>
				</configuration>
			    </load-configuration>
			</xsl:variable>
			<xsl:variable name="policy-out" select="jcs:invoke($policy)"/>
			<!-- If all went well, check configuration and commit -->
			<xsl:choose>
			    <!-- If something went wrong, return error message -->
			    <xsl:when test="$policy-out//xnm:error">
				<xsl:copy-of select="$policy-out//xnm:error"/>
			    </xsl:when>
			    <xsl:otherwise>
				<!-- If everything went well, check and commit -->
				<xsl:variable name="commit-result">
				    <xsl:call-template name="commit-config"/>
				</xsl:variable>
				<xsl:choose>
				    <!-- Configuration commited successfully -->
				    <xsl:when test="$commit-result='true'">
					<output>
					    <xsl:text>BGP policies commited successfully</xsl:text>
					</output>
				    </xsl:when>
				    <!-- Commit failed - return error message -->
				    <xsl:otherwise>
					<xsl:copy-of select="$commit-result"/>
				    </xsl:otherwise>
				</xsl:choose>
			    </xsl:otherwise>
			</xsl:choose>
		    </xsl:when>
		    <!-- If config syntax pre-check failed, return error message-->
		    <xsl:otherwise>
			<xsl:copy-of select="$check-result"/>
		    </xsl:otherwise>
		</xsl:choose>
		<!-- Release configuration lock if it has been locked -->
		<xsl:variable name="unlock-result">
		    <xsl:call-template name="unlock-config"/>
		</xsl:variable>
		<!-- If configuration unlock failed, return error message -->
		<xsl:choose>
		    <xsl:when test="$unlock-result='true'"/>
		    <xsl:otherwise>
			<xsl:copy-of select="$unlock-result"/>
		    </xsl:otherwise>
		</xsl:choose>
	    </xsl:when>
	    <!-- If configuration lock failed, return error message -->
	    <xsl:otherwise>
		<xsl:copy-of select="$lock-result"/>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>

    <xsl:template name="lock-config">
	<!-- Obtain private copy of the configuration -->
	<xsl:variable name="lock-config">
	    <open-configuration>
		<private/>
	    </open-configuration>
	</xsl:variable>
	<xsl:variable name="lock-out" select="jcs:invoke($lock-config)"/>

	<xsl:choose>
	    <!-- If configuration lock fails, display error -->
	    <xsl:when test="$lock-out//xnm:error">
		<xsl:copy-of select="$lock-out//xnm:error"/>
	    </xsl:when>
	    <!-- otherwise, return TRUE -->
	    <xsl:otherwise>
		<xsl:value-of select="'true'"/>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>

    <xsl:template name="unlock-config">
	<!-- Release private copy of the configuration -->
	<xsl:variable name="unlock-config">
	    <close-configuration/>
	</xsl:variable>
	<xsl:variable name="unlock-out" select="jcs:invoke($unlock-config)"/>

	<xsl:choose>
	    <!-- If configuration unlock fails, display error -->
	    <xsl:when test="$unlock-out//xnm:error">
		<xsl:copy-of select="$unlock-out//xnm:error"/>
	    </xsl:when>
	    <!-- otherwise, return TRUE -->
	    <xsl:otherwise>
		<xsl:value-of select="'true'"/>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>

    <xsl:template name="check-config">
	<!-- Check configuration syntax -->
	<xsl:variable name="check-configuration">
	    <commit-configuration>
		<check/>
	    </commit-configuration>
	</xsl:variable>
	<xsl:variable name="check-out" select="jcs:invoke($check-configuration)"/>

	<xsl:choose>
	    <!-- If configuration syntax check fails, display error -->
	    <xsl:when test="$check-out//xnm:error">
		<xsl:copy-of select="$check-out//xnm:error"/>
	    </xsl:when>
	    <!-- otherwise, return TRUE -->
	    <xsl:otherwise>
		<xsl:value-of select="'true'"/>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>

    <xsl:template name="commit-config">
	<!-- Check configuration syntax before commit -->
	<xsl:variable name="check-configuration">
	    <commit-configuration>
		<check/>
	    </commit-configuration>
	</xsl:variable>
	<xsl:variable name="check-out" select="jcs:invoke($check-configuration)"/>

	<xsl:choose>
	    <!-- If configuration syntax check fails, display error -->
	    <xsl:when test="$check-out//xnm:error">
		<xsl:copy-of select="$check-out//xnm:error"/>
	    </xsl:when>
	    <!-- otherwise, commit changes -->
	    <xsl:otherwise>
		<xsl:variable name="commit">
		    <commit-configuration>
			<synchronize/>
		    </commit-configuration>
		</xsl:variable>
		<xsl:variable name="commit-out" select="jcs:invoke($commit)"/>
		<xsl:value-of select="'true'"/>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>

</xsl:stylesheet>
